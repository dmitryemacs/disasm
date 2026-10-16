;;; disasm-objdump.el --- GNU objdump backend for disasm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://example.invalid/disasm

;;; Commentary:

;; Backend that shells out to GNU objdump and parses its output into the
;; data structures defined in `disasm-core'.  Handles PE/COFF, ELF and
;; Mach-O object files transparently, since objdump itself auto-detects the
;; container format.

;;; Code:

(require 'disasm-core)
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

(defconst disasm-objdump--insn-re
  "^[ \t]*\\([0-9a-fA-F]+\\):\t\\([0-9a-fA-F ]*\\)\\(?:\t\\(.*\\)\\)?"
  "Regexp matching a disassembly line: address TAB bytes [TAB instruction].
The instruction part is optional: when objdump wraps a long instruction,
the continuation line carries only the address and the remaining bytes.")

;;; Running objdump

(defun disasm--resolve-program ()
  "Return the path of the objdump executable to use."
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

(defun disasm--normalize-output (output)
  "Normalize objdump OUTPUT by collapsing CRLF line endings to LF."
  (replace-regexp-in-string "\r\n?" "\n" output))

(defun disasm--objdump-run (args)
  "Run objdump with ARGS and return its standard output as a string."
  (let ((program (disasm--resolve-program)))
    (with-temp-buffer
      (let ((status (apply #'call-process program nil (current-buffer) nil args)))
        (if (and (integerp status) (zerop status))
            ;; objdump on Windows/Cygwin emits CRLF; normalize to LF so that
            ;; the rest of the code can rely on plain newlines.
            (disasm--normalize-output (buffer-string))
          (error "objdump failed (status %s, program %s):\n%s"
                 status program (string-trim (buffer-string))))))))

(defun disasm--objdump-run-async (args callback)
  "Run objdump with ARGS in the background.
Call CALLBACK with two arguments when the process finishes: the exit
STATUS (an integer) and the captured OUTPUT (a string).  Errors that
prevent the process from starting are reported to CALLBACK with a
non-numeric status."
  (let* ((program (disasm--resolve-program))
         (buffer (generate-new-buffer " *disasm-objdump*")))
    (condition-case err
        (make-process
         :name "disasm-objdump"
         :buffer buffer
         :command (cons program args)
         :coding 'binary
         :noquery t
         :sentinel
         (lambda (process _event)
           (when (memq (process-status process) '(exit signal))
             (let ((status (process-exit-status process))
                   (output (with-current-buffer buffer (buffer-string))))
               (kill-buffer buffer)
               (funcall callback status (disasm--normalize-output output))))))
      (error
       (kill-buffer buffer)
       (message "disasm: failed to start objdump: %s" (error-message-string err))
       (funcall callback 'error "")))))

;;; Headers and sections

(defun disasm-objdump--parse-header (out)
  "Parse the output OUT of `objdump -f'."
  (list :format (when (string-match "file format \\([^ \t\r\n]+\\)" out)
                  (match-string 1 out))
        :arch (when (string-match "architecture: \\([^,\r\n]+\\)" out)
                (string-trim (match-string 1 out)))
        :entry (when (string-match "start address:?[ \t]+0x\\([0-9a-fA-F]+\\)" out)
                 (string-to-number (match-string 1 out) 16))))

(defun disasm-objdump-header (file &optional raw)
  "Return a plist with :format, :arch and :entry for FILE.
When RAW is non-nil, treat FILE as a headerless binary."
  (disasm-objdump--parse-header
   (disasm--objdump-run
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
   (disasm--objdump-run
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

(defun disasm--insn-kind (mnemonic)
  "Classify MNEMONIC as `call', `jmp' or `other'."
  (cond
   ((member mnemonic '("call" "callq" "lcall")) 'call)
   ((member mnemonic '("jmp" "jmpq" "ljmp")) 'jmp)
   ((member mnemonic '("loop" "loope" "loopne")) 'jmp)
   ((string-prefix-p "j" mnemonic) 'jmp)
   (t 'other)))

(defun disasm--make-insn (addr bytes text section label)
  "Create a `disasm-insn' from ADDR, BYTES, TEXT, SECTION and LABEL."
  (let* ((text (string-trim text))
         (split (string-match "[ \t]" text))
         (mnemonic (if split (substring text 0 split) text))
         (operands (if split (string-trim (substring text split)) ""))
         (bytes (string-trim bytes))
         (insn (disasm-insn--create
                :addr addr
                :bytes bytes
                :mnemonic mnemonic
                :operands operands
                :size (length (split-string bytes "[ \t]+" t))
                :section section
                :label label)))
    (setf (disasm-insn-kind insn) (disasm--insn-kind mnemonic))
    (when (and (memq (disasm-insn-kind insn) '(call jmp))
               (not (string-empty-p operands)))
      (cond
       ((string-match "\\`0x\\([0-9a-fA-F]+\\)" operands)
        (setf (disasm-insn-target insn)
              (string-to-number (match-string 1 operands) 16)))
       ((string-match "\\`\\([0-9a-fA-F]+\\)\\_>" operands)
        (setf (disasm-insn-target insn)
              (string-to-number (match-string 1 operands) 16)))))
    insn))

(defun disasm-objdump--parse-disassembly (out sections)
  "Parse disassembly OUT using SECTIONS for naming.
Return a plist (:insns VECTOR :labels ALIST), where ALIST maps label
names to addresses."
  (let ((table (make-hash-table :test #'equal))
        (insns nil)
        (labels nil)
        (current-section nil)
        (pending-label nil)
        (last nil))
    (dolist (section sections)
      (puthash (disasm-section-name section) section table))
    (dolist (line (split-string out "\n"))
      (cond
       ((string-match "\\`Disassembly of section \\(.*\\):\\'" line)
        (let ((name (match-string 1 line)))
          (setq current-section
                (or (gethash name table)
                    (disasm-section--create :name name)))))
       ((string-match "\\`\\([0-9a-fA-F]+\\) <\\(.*\\)>:\\'" line)
        (setq pending-label (cons (match-string 2 line)
                                  (string-to-number (match-string 1 line) 16))))
       ((string-match disasm-objdump--insn-re line)
        (let ((addr (string-to-number (match-string 1 line) 16))
              (bytes (match-string 2 line))
              (text (or (match-string 3 line) "")))
          (if (string-empty-p (string-trim text))
              (when last
                (setf (disasm-insn-bytes last)
                      (string-trim (concat (disasm-insn-bytes last) " " bytes)))
                (setf (disasm-insn-size last)
                      (length (split-string (disasm-insn-bytes last) "[ \t]+" t))))
            (let* ((label (when pending-label
                            (push pending-label labels)
                            (prog1 (car pending-label)
                              (setq pending-label nil))))
                   (insn (disasm--make-insn addr bytes text current-section label)))
              (push insn insns)
              (setq last insn)))))
       (t nil)))
    (list :insns (vconcat (nreverse insns))
          :labels (nreverse labels))))

(defun disasm-objdump-disassemble (file sections all-sections &optional raw)
  "Disassemble FILE, using SECTIONS for naming.
When ALL-SECTIONS is non-nil, disassemble data sections too.
When RAW is non-nil, treat FILE as a headerless binary.
Return a plist (:insns VECTOR :labels ALIST)."
  (disasm-objdump--parse-disassembly
   (disasm--objdump-run (disasm-objdump--disasm-args file all-sections raw))
   sections))

(defun disasm-objdump-disassemble-async (file sections all-sections raw callback)
  "Disassemble FILE in the background.
SECTIONS, ALL-SECTIONS and RAW have the same meaning as in
`disasm-objdump-disassemble'.  When the process finishes, call CALLBACK
with two arguments: the exit STATUS and, on success, the parsed result
plist (otherwise nil)."
  (disasm--objdump-run-async
   (disasm-objdump--disasm-args file all-sections raw)
   (lambda (status output)
     (if (and (integerp status) (zerop status))
         (funcall callback status
                  (disasm-objdump--parse-disassembly output sections))
       (funcall callback status nil)))))

(provide 'disasm-objdump)
;;; disasm-objdump.el ends here
