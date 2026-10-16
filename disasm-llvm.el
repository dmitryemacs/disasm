;;; disasm-llvm.el --- llvm-objdump backend for disasm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://github.com/dmitryemacs/disasm

;;; Commentary:

;; Backend that shells out to llvm-objdump.  It reuses the format-agnostic
;; header and disassembly parsers from `disasm-parse', and only adds the
;; llvm-specific section table parser and command line.
;;
;; llvm-objdump's `-h' output has a different shape from GNU objdump's: it
;; lists \"Idx Name Size VMA Type\" and, crucially, does NOT print the file
;; offset of a section.  The file offsets needed for hex-pane synchronization
;; are recovered separately from the PE/ELF container by `disasm-image'.
;;
;; llvm-objdump cannot disassemble a raw (headerless) binary; use the GNU
;; objdump backend for that.

;;; Code:

(require 'disasm-core)
(require 'disasm-process)
(require 'disasm-parse)
(require 'subr-x)

;;; Section table (`llvm-objdump -h')

(defconst disasm-llvm--section-re
  (concat "^[ \t]*\\([0-9]+\\)"                ; index
          "[ \t]+"
          "\\([^ \t\n]+\\)?"                   ; optional name (absent for index 0)
          "[ \t]+"
          "\\([0-9a-fA-F]+\\)"                 ; size
          "[ \t]+"
          "\\([0-9a-fA-F]+\\)"                 ; vma
          "[ \t]*\\(.*\\)$")                   ; type (possibly empty)
  "Regexp matching a row of `llvm-objdump -h' output.
The name column may be empty; the size and VMA columns are plain
hexadecimal without a fixed width.")

;;; Running llvm-objdump

(defun disasm-llvm--resolve-program ()
  "Return the path of the llvm-objdump executable to use."
  (or (and disasm-llvm-objdump-program
           (or (executable-find disasm-llvm-objdump-program)
               disasm-llvm-objdump-program))
      (cl-loop for candidate in '("D:/Qt/Tools/llvm-mingw2217_64/bin/llvm-objdump.exe"
                                  "llvm-objdump.exe"
                                  "llvm-objdump")
               for found = (executable-find candidate)
               when found return found)
      (user-error "llvm-objdump not found; customize `disasm-llvm-objdump-program'")))

(defun disasm-llvm--check-raw (raw)
  "Signal an error when RAW is non-nil, since llvm-objdump has no such mode."
  (when raw
    (user-error "llvm-objdump cannot disassemble a raw binary; use the GNU objdump backend")))

;;; Headers and sections

(defun disasm-llvm-header (file &optional raw)
  "Return a plist with :format, :arch and :entry for FILE.
When RAW is non-nil, signal an error (unsupported by llvm-objdump)."
  (disasm-llvm--check-raw raw)
  (disasm-parse-header
   (disasm-process-run
    (disasm-llvm--resolve-program)
    (list "-f" (disasm--file-arg file)))))

(defun disasm-llvm--parse-sections (out)
  "Parse the output OUT of `llvm-objdump -h' into a list of `disasm-section'.
The file offset of each section is left nil; it has to be recovered from
the container format (see `disasm-image')."
  (let ((sections nil))
    (dolist (line (split-string out "\n"))
      (when (string-match disasm-llvm--section-re line)
        (let* ((name (match-string 2 line))
               (type (string-trim (or (match-string 5 line) ""))))
          ;; Skip the synthetic index-0 row (no name, no size).
          (unless (and (or (null name) (string-empty-p name))
                       (equal (match-string 3 line) "00000000"))
            (push (disasm-section--create
                   :name (if (or (null name) (string-empty-p name))
                             (format "<section-%s>" (match-string 1 line))
                           name)
                   :size (string-to-number (match-string 3 line) 16)
                   :vma (string-to-number (match-string 4 line) 16)
                   :fileoff nil
                   :flags type
                   :code-p (and (string-match-p "TEXT\\|CODE" type) t))
                  sections)))))
    (nreverse sections)))

(defun disasm-llvm-sections (file &optional raw)
  "Return the list of `disasm-section' structs for FILE.
When RAW is non-nil, signal an error (unsupported by llvm-objdump)."
  (disasm-llvm--check-raw raw)
  (disasm-llvm--parse-sections
   (disasm-process-run
    (disasm-llvm--resolve-program)
    (list "-h" (disasm--file-arg file)))))

;;; Disassembly

(defun disasm-llvm--disasm-args (file all-sections &optional raw)
  "Return the llvm-objdump argument list for disassembling FILE.
When RAW is non-nil, signal an error (unsupported by llvm-objdump)."
  (disasm-llvm--check-raw raw)
  (append
   (list (if all-sections "-D" "-d"))
   (when (eq disasm-syntax 'intel) (list "--x86-asm-syntax=intel"))
   (when disasm-demangle (list "-C"))
   disasm-llvm-objdump-extra-args
   (list (disasm--file-arg file))))

(defun disasm-llvm-disassemble (file sections all-sections &optional raw)
  "Disassemble FILE, using SECTIONS for naming.
When ALL-SECTIONS is non-nil, disassemble data sections too.
When RAW is non-nil, signal an error (unsupported by llvm-objdump).
Return a plist (:insns VECTOR :labels ALIST)."
  (disasm-parse-disassembly
   (disasm-process-run
    (disasm-llvm--resolve-program)
    (disasm-llvm--disasm-args file all-sections raw))
   sections))

(defun disasm-llvm-disassemble-async (file sections all-sections raw callback)
  "Disassemble FILE in the background with llvm-objdump.
SECTIONS, ALL-SECTIONS and RAW have the same meaning as in
`disasm-llvm-disassemble'.  When the process finishes, call CALLBACK with
two arguments: the exit STATUS and, on success, the parsed result plist
\(otherwise nil)."
  (disasm-process-run-async
   (disasm-llvm--resolve-program)
   (disasm-llvm--disasm-args file all-sections raw)
   (lambda (status output)
     (if (and (integerp status) (zerop status))
         (funcall callback status
                  (disasm-parse-disassembly output sections))
       (funcall callback status nil)))))

(provide 'disasm-llvm)
;;; disasm-llvm.el ends here
