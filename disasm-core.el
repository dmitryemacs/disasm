;;; disasm-core.el --- Core types and options for disasm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://example.invalid/disasm

;;; Commentary:

;; Shared customization options, faces, data structures and small helpers
;; used by the rest of the `disasm' package.  Do not use this file
;; directly; load `disasm.el' instead.

;;; Code:

(require 'cl-lib)
(require 'subr-x)

;;; Customization

(defgroup disasm nil
  "Interactively disassemble binaries with an external objdump."
  :group 'tools
  :prefix "disasm-")

(defcustom disasm-backend 'objdump
  "Disassembly backend to use."
  :type '(choice (const :tag "GNU objdump" objdump)
                 (const :tag "LLVM objdump" llvm-objdump))
  :group 'disasm)

(defcustom disasm-objdump-program nil
  "Absolute path to the GNU objdump executable.
When nil, `disasm' auto-detects a suitable binary (Cygwin, MinGW or
whatever is found on `exec-path')."
  :type '(choice (const :tag "Auto-detect" nil) file)
  :group 'disasm)

(defcustom disasm-llvm-objdump-program nil
  "Absolute path to the llvm-objdump executable.
When nil, `disasm' auto-detects a suitable binary (common Qt/LLVM
installations or whatever is found on `exec-path')."
  :type '(choice (const :tag "Auto-detect" nil) file)
  :group 'disasm)

(defcustom disasm-syntax 'intel
  "Assembly syntax passed to objdump."
  :type '(choice (const :tag "Intel" intel)
                 (const :tag "AT&T" att))
  :group 'disasm)

(defcustom disasm-demangle t
  "When non-nil, ask objdump to demangle C++ symbols."
  :type 'boolean
  :group 'disasm)

(defcustom disasm-show-bytes t
  "When non-nil, show the raw instruction bytes in the listing."
  :type 'boolean
  :group 'disasm)

(defcustom disasm-fontify-limit 40000
  "Maximum number of instructions for which operands are highlighted.
Above this limit the listing is rendered with fewer text properties,
which is considerably faster for very large binaries.  Set to nil to
always highlight operands."
  :type '(choice (const :tag "Unlimited" nil) integer)
  :group 'disasm)

(defcustom disasm-disassemble-all nil
  "When non-nil, disassemble every section instead of code sections only."
  :type 'boolean
  :group 'disasm)

(defcustom disasm-objdump-extra-args nil
  "Extra command line arguments passed to objdump."
  :type '(repeat string)
  :group 'disasm)

(defcustom disasm-llvm-objdump-extra-args nil
  "Extra command line arguments passed to llvm-objdump."
  :type '(repeat string)
  :group 'disasm)

(defcustom disasm-bind-prefix t
  "When non-nil, bind the `disasm' command prefix to \"C-c d\"."
  :type 'boolean
  :group 'disasm)

(defcustom disasm-hex-max-bytes (* 64 1024 1024)
  "Maximum number of file bytes rendered in the hex pane.
Larger files are truncated in the hex pane to keep Emacs responsive."
  :type 'integer
  :group 'disasm)

(defcustom disasm-outline-width 30
  "Width of the right sidebar (sections/functions) as a percentage.
Used by the docked layout of `disasm-open'."
  :type 'integer
  :group 'disasm)

(defcustom disasm-hex-height 35
  "Height of the hex pane as a percentage of the left column.
Used by the docked layout of `disasm-open'."
  :type 'integer
  :group 'disasm)

(defcustom disasm-outline-split 40
  "Height of the sections pane as a percentage of the right sidebar.
The functions pane fills the rest.  Used by the docked layout of
`disasm-open'."
  :type 'integer
  :group 'disasm)

(defcustom disasm-raw-arch "i386:x86-64"
  "Default architecture passed to objdump for raw (headerless) binaries.
Used by `disasm-open-raw' together with the \"-b binary\" option."
  :type 'string
  :group 'disasm)

(defcustom disasm-raw-base 0
  "Default base address used when disassembling a raw binary.
The value is passed to objdump as `--adjust-vma'."
  :type 'integer
  :group 'disasm)

;;; Faces

(defface disasm-address-face
  '((t :inherit font-lock-constant-face))
  "Face for the address column."
  :group 'disasm)

(defface disasm-bytes-face
  '((t :inherit font-lock-comment-face))
  "Face for the raw bytes column."
  :group 'disasm)

(defface disasm-mnemonic-face
  '((t :inherit font-lock-keyword-face))
  "Face for instruction mnemonics."
  :group 'disasm)

(defface disasm-register-face
  '((t :inherit font-lock-variable-name-face))
  "Face for register names in operands."
  :group 'disasm)

(defface disasm-immediate-face
  '((t :inherit font-lock-constant-face))
  "Face for immediate values in operands."
  :group 'disasm)

(defface disasm-symbol-face
  '((t :inherit font-lock-function-name-face))
  "Face for symbol references such as <main+0x10>."
  :group 'disasm)

(defface disasm-comment-face
  '((t :inherit font-lock-comment-face))
  "Face for objdump comments."
  :group 'disasm)

(defface disasm-section-face
  '((t :inherit font-lock-preprocessor-face :weight bold))
  "Face for section header lines."
  :group 'disasm)

(defface disasm-label-face
  '((t :inherit font-lock-function-name-face :weight bold))
  "Face for label lines."
  :group 'disasm)

(defface disasm-target-face
  '((t :inherit link :underline nil))
  "Face for clickable branch/call targets."
  :group 'disasm)

(defface disasm-hex-offset-face
  '((t :inherit font-lock-comment-face))
  "Face for the file-offset column of the hex pane."
  :group 'disasm)

(defface disasm-hex-vaddr-face
  '((t :inherit font-lock-constant-face))
  "Face for the virtual-address column of the hex pane."
  :group 'disasm)

(defface disasm-hex-bytes-face
  '((t :inherit default))
  "Face for the hex bytes column of the hex pane."
  :group 'disasm)

(defface disasm-hex-ascii-face
  '((t :inherit font-lock-string-face))
  "Face for the ASCII column of the hex pane."
  :group 'disasm)

(defface disasm-hex-highlight-face
  '((t :background "gray30" :foreground "white" :extend t))
  "Face highlighting the bytes of the current instruction in the hex pane."
  :group 'disasm)

;;; Data structures

(cl-defstruct (disasm-section (:constructor disasm-section--create))
  "A section of the binary."
  name vma size fileoff flags code-p)

(cl-defstruct (disasm-insn (:constructor disasm-insn--create))
  "A single decoded instruction."
  addr bytes mnemonic operands size target kind label section line)

(cl-defstruct (disasm-session (:constructor disasm-session--create))
  "A disassembly session for one file."
  file format arch bits backend
  sections insns symbols entry
  show-bytes all-sections
  buffer hex-buffer
  sections-buffer functions-buffer
  (state 'ready) raw error)

;;; Helpers

(defconst disasm-register-regexp
  (regexp-opt
   '("rax" "rbx" "rcx" "rdx" "rsi" "rdi" "rbp" "rsp" "rip"
     "eax" "ebx" "ecx" "edx" "esi" "edi" "ebp" "esp" "eip"
     "ax" "bx" "cx" "dx" "si" "di" "bp" "sp" "ip"
     "al" "bl" "cl" "dl" "ah" "bh" "ch" "dh"
     "sil" "dil" "bpl" "spl"
     "r8" "r9" "r10" "r11" "r12" "r13" "r14" "r15"
     "r8d" "r9d" "r10d" "r11d" "r12d" "r13d" "r14d" "r15d"
     "r8w" "r9w" "r10w" "r11w" "r12w" "r13w" "r14w" "r15w"
     "r8b" "r9b" "r10b" "r11b" "r12b" "r13b" "r14b" "r15b"
     "cs" "ds" "es" "fs" "gs" "ss"
     "st0" "st1" "st2" "st3" "st4" "st5" "st6" "st7"
     "xmm0" "xmm1" "xmm2" "xmm3" "xmm4" "xmm5" "xmm6" "xmm7"
     "ymm0" "ymm1" "zmm0")
   'symbols)
  "Regexp matching common x86 register names.")

(defun disasm--file-arg (file)
  "Return FILE with forward slashes, suitable for passing to objdump."
  (replace-regexp-in-string "\\\\" "/" file))

(defun disasm--hex-to-int (string)
  "Parse STRING as a hexadecimal number, tolerating a 0x prefix."
  (string-to-number
   (string-remove-prefix "0X" (string-remove-prefix "0x" (string-trim string)))
   16))

(defun disasm--format-address (addr bits)
  "Format integer ADDR as a hexadecimal address of BITS width."
  (format (if (> bits 32) "0x%016x" "0x%08x") addr))

(defun disasm--hex-string-to-unibyte (hex)
  "Decode the hexadecimal string HEX into a unibyte string.
HEX is a run of an even number of hexadecimal digits, as returned by
GDB/MI when reading target memory.  An odd trailing digit is dropped."
  (let ((n (/ (length hex) 2))
        (bytes nil))
    (dotimes (i n)
      (push (string-to-number (substring hex (* i 2) (+ (* i 2) 2)) 16)
            bytes))
    (apply #'unibyte-string (nreverse bytes))))

(defun disasm--unibyte-to-hex (bytes)
  "Encode the unibyte string BYTES as a lowercase hexadecimal string."
  (mapconcat (lambda (byte) (format "%02x" byte)) (append bytes nil) ""))

(defun disasm--unibyte-to-int (bytes &optional start count)
  "Read COUNT little-endian bytes of BYTES starting at START as an integer.
COUNT defaults to the length of BYTES minus START."
  (let* ((start (or start 0))
         (count (or count (- (length bytes) start)))
         (value 0))
    (dotimes (i count)
      (setq value (+ value (ash (aref bytes (+ start i)) (* 8 i)))))
    value))

(defun disasm--align-down (value align)
  "Return VALUE rounded down to a multiple of ALIGN."
  (if (and (integerp align) (> align 0))
      (- value (% value align))
    value))

;;; Synchronization hooks

(defvar-local disasm--sync-driver nil
  "Buffer-local function driving two-pane synchronization.
When non-nil it is called with the selected window by
`disasm-sync--tick' instead of the default file-based behaviour.
The debugger installs such a driver to keep a live hex pane in step
with the listing.")
(put 'disasm--sync-driver 'permanent-local t)

(defun disasm--plain-address (addr bits)
  "Format integer ADDR like objdump does, without the 0x prefix."
  (format (if (> bits 32) "%016x" "%08x") addr))

;;; Session queries (binary search over the sorted instruction vector)

(defun disasm-session-insn-index-for-addr (session addr)
  "Return the index of the last instruction whose address is <= ADDR.
Return nil when SESSION has no instructions."
  (let* ((v (disasm-session-insns session))
         (n (length v)))
    (when (> n 0)
      (let ((lo 0) (hi (1- n)) (ans nil))
        (while (<= lo hi)
          (let* ((mid (/ (+ lo hi) 2))
                 (a (disasm-insn-addr (aref v mid))))
            (if (<= a addr)
                (progn (setq ans mid) (setq lo (1+ mid)))
              (setq hi (1- mid)))))
        (or ans 0)))))

(defun disasm-session-insn-index-exact (session addr)
  "Return the index of the instruction whose address equals ADDR, or nil."
  (let ((idx (disasm-session-insn-index-for-addr session addr)))
    (when (and idx (= (disasm-insn-addr (aref (disasm-session-insns session) idx)) addr))
      idx)))

(defun disasm-session-insn-index-at-line (session line)
  "Return the index of the last instruction whose line is <= LINE.
Return nil when LINE precedes the first instruction."
  (let* ((v (disasm-session-insns session))
         (n (length v)))
    (when (> n 0)
      (let ((lo 0) (hi (1- n)) (ans nil))
        (while (<= lo hi)
          (let* ((mid (/ (+ lo hi) 2))
                 (l (disasm-insn-line (aref v mid))))
            (if (<= l line)
                (progn (setq ans mid) (setq lo (1+ mid)))
              (setq hi (1- mid)))))
        ans))))

(provide 'disasm-core)
;;; disasm-core.el ends here
