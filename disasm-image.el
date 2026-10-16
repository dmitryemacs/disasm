;;; disasm-image.el --- PE/ELF section table reader for disasm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://github.com/dmitryemacs/disasm

;;; Commentary:

;; A small reader for the section tables of PE/COFF and ELF files.  It
;; exists to recover the file offset of each section, which llvm-objdump's
;; `-h' output does not include; the hex pane needs those offsets to map
;; between file positions and virtual addresses.
;;
;; Only the headers are read (a few kilobytes), never the whole file, so it
;; stays cheap even for large binaries.  The results are `disasm-section'
;; structs with :name, :vma, :size (the on-disk size) and :fileoff; sections
;; without file content (such as .bss / SHT_NOBITS) are omitted.

;;; Code:

(require 'disasm-core)
(require 'cl-lib)
(require 'subr-x)

;;; Low-level byte readers

(defun disasm-image--read (file beg end)
  "Return FILE's bytes between BEG and END as a unibyte string."
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (insert-file-contents-literally file nil beg end)
    (buffer-string)))

(defun disasm-image--u16 (str off le)
  "Read an unsigned 16-bit integer from STR at OFF.
When LE is non-nil, interpret the bytes as little-endian.  Return nil
when STR is too short."
  (when (<= (+ off 2) (length str))
    (let ((b0 (aref str off))
          (b1 (aref str (1+ off))))
      (if le (+ b0 (ash b1 8)) (+ (ash b0 8) b1)))))

(defun disasm-image--u32 (str off le)
  "Read an unsigned 32-bit integer from STR at OFF.
When LE is non-nil, interpret the bytes as little-endian.  Return nil
when STR is too short."
  (when (<= (+ off 4) (length str))
    (if le
        (+ (aref str off)
           (ash (aref str (+ off 1)) 8)
           (ash (aref str (+ off 2)) 16)
           (ash (aref str (+ off 3)) 24))
      (+ (ash (aref str off) 24)
         (ash (aref str (+ off 1)) 16)
         (ash (aref str (+ off 2)) 8)
         (aref str (+ off 3))))))

(defun disasm-image--u64 (str off le)
  "Read an unsigned 64-bit integer from STR at OFF.
When LE is non-nil, interpret the bytes as little-endian.  Return nil
when STR is too short."
  (when (<= (+ off 8) (length str))
    (let ((value 0))
      (dotimes (i 8)
        (let ((byte (aref str (+ off i))))
          (setq value (+ value (ash byte (if le (* 8 i) (* 8 (- 7 i))))))))
      value)))

(defun disasm-image--string (str off maxlen)
  "Return the NUL-terminated string in STR at OFF, at most MAXLEN bytes."
  (let ((end off)
        (limit (min (length str) (+ off maxlen))))
    (while (and (< end limit) (/= (aref str end) 0))
      (setq end (1+ end)))
    (substring str off end)))

;;; PE / COFF

(defconst disasm-image--pe-machine-64 #x8664
  "PE machine value for x86-64.")
(defconst disasm-image--pe-machine-arm64 #xaa64
  "PE machine value for ARM64.")

(defun disasm-image--pe-info (file)
  "Return section information for the PE file FILE, or nil.
The result is a plist (:kind :bits :entry :sections)."
  (let ((dos (disasm-image--read file 0 64)))
    (when (and (>= (length dos) 64)
               (string= (substring dos 0 2) "MZ"))
      (let ((lfanew (disasm-image--u32 dos #x3C t)))
        (when (and lfanew (<= (+ lfanew 24) (or (file-attribute-size
                                                  (file-attributes file)) 0)))
          (let ((coff (disasm-image--read file lfanew (+ lfanew 24))))
            (when (and (>= (length coff) 24)
                       (string= (substring coff 0 4) "PE\0\0"))
              (let* ((machine (disasm-image--u16 coff 4 t))
                     (nsec (disasm-image--u16 coff 6 t))
                     (optsize (disasm-image--u16 coff 20 t))
                     (optoff (+ lfanew 24))
                     (opt (disasm-image--read file optoff (+ optoff optsize)))
                     (magic (disasm-image--u16 opt 0 t))
                     (pe32+ (eql magic #x20b))
                     (entry-rva (disasm-image--u32 opt 16 t))
                     (image-base (if pe32+
                                     (disasm-image--u64 opt 24 t)
                                   (disasm-image--u32 opt 28 t)))
                     (sectoff (+ optoff optsize))
                     (raw (disasm-image--read file sectoff (+ sectoff (* nsec 40))))
                     (sections nil))
                (dotimes (i nsec)
                  (let ((off (* i 40)))
                    (let* ((name (string-trim-right
                                  (disasm-image--string raw off 8)
                                  "[\0 ]+"))
                           (va (disasm-image--u32 raw (+ off 12) t))
                           (rawsize (disasm-image--u32 raw (+ off 16) t))
                           (rawptr (disasm-image--u32 raw (+ off 20) t)))
                      ;; Only sections with bytes on disk are useful for the
                      ;; hex pane; skip .bss-style sections (raw size 0).
                      (when (and rawsize rawptr (> rawsize 0) (> rawptr 0)
                                 (not (string-empty-p name)))
                        (push (disasm-section--create
                               :name name
                               :vma (+ (or image-base 0) (or va 0))
                               :size rawsize
                               :fileoff rawptr
                               :flags " CONTENTS")
                              sections)))))
                (list :kind 'pe
                      :bits (if (or (eql machine disasm-image--pe-machine-64)
                                    (eql machine disasm-image--pe-machine-arm64))
                                64 32)
                      :entry (and entry-rva image-base
                                  (+ image-base entry-rva))
                      :sections (nreverse sections))))))))))

;;; ELF

(defconst disasm-image--sht-nobits 8
  "ELF SHT_NOBITS section type (occupies no file space).")

(defun disasm-image--elf-info (file)
  "Return section information for the ELF file FILE, or nil.
The result is a plist (:kind :bits :entry :sections)."
  (let ((head (disasm-image--read file 0 64)))
    (when (and (>= (length head) 52)
               (string= (substring head 0 4) "\177ELF"))
      (let* ((class (aref head 4))                 ; 1 = 32-bit, 2 = 64-bit
             (data (aref head 5))                  ; 1 = LE, 2 = BE
             (le (eql data 1))
             (bits (if (eql class 2) 64 32))
             (shoff (if (eql bits 64)
                        (disasm-image--u64 head #x28 le)
                      (disasm-image--u32 head #x20 le)))
             (shentsize (disasm-image--u16 head (if (eql bits 64) #x3A #x2E) le))
             (shnum (disasm-image--u16 head (if (eql bits 64) #x3C #x30) le))
             (shstrndx (disasm-image--u16 head (if (eql bits 64) #x3E #x32) le)))
        (when (and shoff shentsize shnum (> shnum 0))
          (let* ((table (disasm-image--read file shoff
                                            (+ shoff (* shnum shentsize))))
                 (addr-off (if (eql bits 64) #x10 #x0C))
                 (size-off (if (eql bits 64) #x20 #x14))
                 (off-off (if (eql bits 64) #x18 #x10))
                 (read-int (if (eql bits 64)
                               (lambda (o) (disasm-image--u64 table o le))
                             (lambda (o) (disasm-image--u32 table o le))))
                 (read-size (lambda (o)
                              (if (eql bits 64)
                                  (disasm-image--u64 table o le)
                                (disasm-image--u32 table o le)))))
            ;; Locate the section-header string table, then the raw sections.
            (let* ((strtab-base (* shstrndx shentsize))
                   (strtab-off (funcall read-int (+ strtab-base off-off)))
                   (strtab-size (funcall read-size (+ strtab-base size-off)))
                   (strtab (and strtab-off strtab-size (> strtab-size 0)
                                (disasm-image--read file strtab-off
                                                    (+ strtab-off strtab-size))))
                   (sections nil))
              (dotimes (i shnum)
                (let* ((base (* i shentsize))
                       (sh-name (disasm-image--u32 table base le))
                       (sh-type (disasm-image--u32 table (+ base 4) le))
                       (sh-addr (funcall read-int (+ base addr-off)))
                       (sh-off (funcall read-int (+ base off-off)))
                       (sh-size (funcall read-size (+ base size-off)))
                       (name (if (and strtab sh-name (< sh-name (length strtab)))
                                 (disasm-image--string strtab sh-name
                                                       (- (length strtab) sh-name))
                               "")))
                  (when (and name (not (string-empty-p name))
                             (/= (or sh-type 0) disasm-image--sht-nobits)
                             sh-off sh-size (> sh-size 0))
                    (push (disasm-section--create
                           :name name
                           :vma (or sh-addr 0)
                           :size sh-size
                           :fileoff sh-off
                           :flags " CONTENTS")
                          sections))))
              (list :kind 'elf
                    :bits bits
                    :entry (if (eql bits 64)
                               (disasm-image--u64 head #x18 le)
                             (disasm-image--u32 head #x18 le))
                    :sections (nreverse sections)))))))))

;;; Public API

(defun disasm-image-info (file)
  "Return container information for FILE, or nil.
Return a plist (:kind :bits :entry :sections) for PE and ELF files;
return nil for anything else (including raw binaries)."
  (condition-case nil
      (or (disasm-image--pe-info file)
          (disasm-image--elf-info file))
    (error nil)))

(defun disasm-image--find-by-name (sections name)
  "Return the section in SECTIONS whose name matches NAME, or nil."
  (when (and name (not (string-empty-p name)))
    (or (cl-find name sections
                 :key #'disasm-section-name :test #'string=)
        (cl-find (downcase name) sections
                 :key (lambda (s) (downcase (disasm-section-name s)))
                 :test #'string=))))

(defun disasm-image--find-by-vma (sections vma)
  "Return the unique section in SECTIONS whose VMA equals VMA, or nil.
Sections at address 0 are never matched, since they are ambiguous."
  (when (and (integerp vma) (/= vma 0))
    (let ((hits (cl-remove-if-not (lambda (s) (= (disasm-section-vma s) vma))
                                  sections)))
      (when (= (length hits) 1) (car hits)))))

(defun disasm-image-fill-offsets (info sections)
  "Fill in missing file offsets in SECTIONS using container INFO.
Sections whose `disasm-section-fileoff' is already an integer are left
unchanged.  Sections matched to a container section by name (or, failing
that, by virtual address) get that section's file offset and are marked as
having file contents.  Return SECTIONS."
  (let ((images (and info (plist-get info :sections))))
    (when images
      (dolist (s sections)
        (unless (integerp (disasm-section-fileoff s))
          (let ((match (or (disasm-image--find-by-name images
                                                       (disasm-section-name s))
                           (disasm-image--find-by-vma images
                                                      (disasm-section-vma s)))))
            (when match
              (setf (disasm-section-fileoff s) (disasm-section-fileoff match))
              (setf (disasm-section-flags s)
                    (concat (or (disasm-section-flags s) "") " CONTENTS"))))))))
  sections)

(provide 'disasm-image)
;;; disasm-image.el ends here
