;;; disasm-objdump.el --- GNU objdump backend for disasm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://github.com/dmitryemacs/disasm

;;; Commentary:

;; Backend that shells out to GNU objdump.  Handles PE/COFF, ELF and
;; Mach-O object files transparently, since objdump itself auto-detects the
;; container format.  Also supports headerless (raw) binaries through the
;; \"-b binary\" option, which llvm-objdump does not provide.

;;; Code:

(require 'disasm-core)
(require 'disasm-process)
(require 'disasm-parse)
(require 'subr-x)

;;; Objdump output grammar

(defconst disasm-objdump--section-re
  (concat "^[ \t]*\\([0-9]+\\)"                ; index
          "[ \t]+\\(\\S-+\\)"                  ; name
          "[ \t]+\\([0-9a-fA-F]+\\)"           ; size
          "[ \t]+\\([0-9a-fA-F]+\\)"           ; vma
          "[ \t]+\\([0-9a-fA-F]+\\)"           ; lma
          "[ \t]+\\([0-9a-fA-F]+\\)"           ; file offset
          "[ \t]+\\(2\\*\\*[0-9]+\\)")         ; alignment
  "Regexp matching a row of `objdump -h' output.")

(defconst disasm-objdump--flags-re
  "^[ \t]+\\([A-Z0-9_,]+[A-Z0-9_, ]*\\)[ \t]*$"
  "Regexp matching the flags line under a section row.")

;;; Running objdump

(defun disasm-objdump--resolve-program ()
  "Return the path of the GNU objdump executable to use."
  (or (and disasm-objdump-program
           (or (executable-find disasm-objdump-program)
               disasm-objdump-program))
      (cl-loop for candidate in '("C:/cygwin64/bin/objdump.exe"
                                  "C:/cygwin/bin/objdump.exe"
                                  "C:/msys64/usr/bin/objdump.exe"
                                  "objdump")
               for found = (executable-find candidate)
               when found return found)
      (user-error "objdump not found; customize `disasm-objdump-program'")))

(defun disasm-objdump--raw-args (raw)
  "Return objdump options for disassembling a raw binary.
RAW is nil or a plist with :arch and :base."
  (when raw
    (append (list "-b" "binary")
            (when (plist-get raw :arch)
              (list "-m" (plist-get raw :arch)))
            (when (plist-get raw :base)
              (list (format "--adjust-vma=0x%x" (plist-get raw :base)))))))

;;; Headers and sections

(defun disasm-objdump-header (file &optional raw)
  "Return a plist with :format, :arch and :entry for FILE.
When RAW is non-nil, treat FILE as a headerless binary."
  (disasm-parse-header
   (disasm-process-run
    (disasm-objdump--resolve-program)
    (append (disasm-objdump--raw-args raw)
            (list "-f" (disasm--file-arg file))))))

(defun disasm-objdump--parse-sections (out)
  "Parse the output OUT of `objdump -h' into a list of `disasm-section'."
  (let ((sections nil)
        (current nil))
    (dolist (line (split-string out "\n"))
      (cond
       ((string-match disasm-objdump--section-re line)
        (setq current
              (disasm-section--create
               :name (match-string 2 line)
               :size (string-to-number (match-string 3 line) 16)
               :vma (string-to-number (match-string 4 line) 16)
               :fileoff (string-to-number (match-string 6 line) 16)))
        (push current sections))
       ((and current (string-match disasm-objdump--flags-re line))
        (let ((flags (match-string 1 line)))
          (setf (disasm-section-flags current)
                (concat (or (disasm-section-flags current) "") " " flags))
          (setf (disasm-section-code-p current)
                (string-match-p "\\bCODE\\b" flags))))))
    (nreverse sections)))

(defun disasm-objdump-sections (file &optional raw)
  "Return the list of `disasm-section' structs for FILE.
When RAW is non-nil, treat FILE as a headerless binary."
  (disasm-objdump--parse-sections
   (disasm-process-run
    (disasm-objdump--resolve-program)
    (append (disasm-objdump--raw-args raw)
            (list "-h" (disasm--file-arg file))))))

;;; Disassembly

(defun disasm-objdump--disasm-args (file all-sections &optional raw)
  "Return the objdump argument list for disassembling FILE.
When RAW is non-nil, prepend the raw-binary options."
  (append
   (disasm-objdump--raw-args raw)
   (list (if all-sections "-D" "-d") "--insn-width=16")
   (when (eq disasm-syntax 'intel) (list "-M" "intel"))
   (when disasm-demangle (list "-C"))
   disasm-objdump-extra-args
   (list (disasm--file-arg file))))

(defun disasm-objdump-disassemble (file sections all-sections &optional raw)
  "Disassemble FILE, using SECTIONS for naming.
When ALL-SECTIONS is non-nil, disassemble data sections too.
When RAW is non-nil, treat FILE as a headerless binary.
Return a plist (:insns VECTOR :labels ALIST)."
  (disasm-parse-disassembly
   (disasm-process-run
    (disasm-objdump--resolve-program)
    (disasm-objdump--disasm-args file all-sections raw))
   sections))

(defun disasm-objdump-disassemble-async (file sections all-sections raw callback)
  "Disassemble FILE in the background.
SECTIONS, ALL-SECTIONS and RAW have the same meaning as in
`disasm-objdump-disassemble'.  When the process finishes, call CALLBACK
with two arguments: the exit STATUS and, on success, the parsed result
plist (otherwise nil)."
  (disasm-process-run-async
   (disasm-objdump--resolve-program)
   (disasm-objdump--disasm-args file all-sections raw)
   (lambda (status output)
     (if (and (integerp status) (zerop status))
         (funcall callback status
                  (disasm-parse-disassembly output sections))
       (funcall callback status nil)))))

(provide 'disasm-objdump)
;;; disasm-objdump.el ends here
