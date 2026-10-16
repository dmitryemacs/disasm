;;; disasm-parse.el --- Format-agnostic objdump output parsers  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://github.com/dmitryemacs/disasm

;;; Commentary:

;; Parsers shared by the objdump backends.  GNU objdump and llvm-objdump
;; emit similar but not identical text; the regexps here accept both.  In
;; particular llvm-objdump separates the address from the bytes with a
;; space (GNU uses a tab) and separates the mnemonic from its operands with
;; a tab, so the parsers are intentionally lax about whitespace.

;;; Code:

(require 'disasm-core)
(require 'subr-x)

;;; Header (`objdump -f')

(defconst disasm--header-format-re
  "file format \\([^ \t\r\n]+\\)"
  "Regexp matching the \"file format\" line of `objdump -f'.")

(defconst disasm--header-arch-re
  "architecture: \\([^,\r\n]+\\)"
  "Regexp matching the \"architecture:\" line of `objdump -f'.")

(defconst disasm--header-entry-re
  "start address:?[ \t]+0x\\([0-9a-fA-F]+\\)"
  "Regexp matching the \"start address\" line of `objdump -f'.
The colon is optional because GNU objdump prints \"start address 0x...\"
while llvm-objdump prints \"start address: 0x...\".")

(defun disasm-parse-header (out)
  "Parse the output OUT of `objdump -f'.
Return a plist with :format, :arch and :entry (all optional)."
  (list :format (when (string-match disasm--header-format-re out)
                  (match-string 1 out))
        :arch (when (string-match disasm--header-arch-re out)
                (string-trim (match-string 1 out)))
        :entry (when (string-match disasm--header-entry-re out)
                 (string-to-number (match-string 1 out) 16))))

;;; Disassembly (`objdump -d'/`-D')

(defconst disasm--insn-re
  (concat "^[ \t]*\\([0-9a-fA-F]+\\):"   ; address
          "[ \t]+\\([0-9a-fA-F ]*\\)"    ; raw bytes (hex pairs, space separated)
          "\\(?:\t\\(.*\\)\\)?")         ; instruction text (nil on a continuation line)
  "Regexp matching a disassembly line from GNU objdump or llvm-objdump.
Group 1 is the address, group 2 the raw bytes and group 3 the instruction
text.  Group 3 is nil when llvm-objdump wraps a long instruction, in which
case the line carries only the address and the remaining bytes.")

(defconst disasm--label-re
  "\\`\\([0-9a-fA-F]+\\) <\\(.*\\)>:\\'"
  "Regexp matching a symbol label line such as \"0000000000401000 <main>:\".")

(defconst disasm--section-line-re
  "\\`Disassembly of section \\(.*\\):\\'"
  "Regexp matching a \"Disassembly of section\" header line.")

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

(defun disasm-parse-disassembly (out sections)
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
       ((string-match disasm--section-line-re line)
        (let ((name (match-string 1 line)))
          (setq current-section
                (or (gethash name table)
                    (disasm-section--create :name name)))))
       ((string-match disasm--label-re line)
        (setq pending-label (cons (match-string 2 line)
                                  (string-to-number (match-string 1 line) 16))))
       ((string-match disasm--insn-re line)
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

(provide 'disasm-parse)
;;; disasm-parse.el ends here
