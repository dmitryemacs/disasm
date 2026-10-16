;;; disasm-debug-core.el --- Shared types for disasm debugging  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://github.com/dmitryemacs/disasm

;;; Commentary:

;; Customization options, faces, data structures and small helpers shared
;; by the debugging layer of `disasm'.  The backend-specific code lives in
;; `disasm-debug-gdb'; the user interface lives in `disasm-debug'.  This
;; file is intentionally backend-agnostic so that another debugger can be
;; added without touching the rest of the package.

;;; Code:

(require 'cl-lib)
(require 'subr-x)
(require 'disasm-core)

;;; Customization

(defcustom disasm-debug-backend 'gdb-mi
  "Debugger backend used for live debugging."
  :type '(choice (const :tag "GDB (MI)" gdb-mi))
  :group 'disasm)

(defcustom disasm-debug-program nil
  "Absolute path to the GDB executable.
When nil, `disasm' auto-detects a suitable binary (MinGW, MSYS2,
Cygwin or whatever is found on `exec-path')."
  :type '(choice (const :tag "Auto-detect" nil) file)
  :group 'disasm)

(defcustom disasm-debug-sidebar-width 34
  "Width of the registers/flags/stack column, as a percentage.
Used by the debug layout of `disasm-attach'."
  :type 'integer
  :group 'disasm)

(defcustom disasm-registers-split 45
  "Height of the registers pane, as a percentage of the debug column.
The flags pane takes `disasm-flags-split' percent and the stack pane
fills the rest."
  :type 'integer
  :group 'disasm)

(defcustom disasm-flags-split 22
  "Height of the flags pane, as a percentage of the debug column."
  :type 'integer
  :group 'disasm)

(defcustom disasm-debug-memory-window #x4000
  "Number of bytes of live memory disassembled around the program counter.
Used when the program counter lies outside the module held in a file."
  :type 'integer
  :group 'disasm)

;;; Faces

(defface disasm-debug-pc-face
  '((t :inherit highlight :weight bold :extend t))
  "Face highlighting the instruction at the program counter."
  :group 'disasm)

(defface disasm-debug-frame-current-face
  '((t :inherit highlight :extend t))
  "Face highlighting the current (innermost) stack frame."
  :group 'disasm)

(defface disasm-debug-pane-title-face
  '((t :inherit font-lock-keyword-face :weight bold))
  "Face for the title line of a debug pane."
  :group 'disasm)

(defface disasm-debug-flag-set-face
  '((t :inherit font-lock-warning-face :weight bold))
  "Face marking a set CPU flag."
  :group 'disasm)

(defface disasm-debug-flag-clear-face
  '((t :inherit shadow))
  "Face marking a clear CPU flag."
  :group 'disasm)

(defface disasm-debug-register-name-face
  '((t :inherit font-lock-variable-name-face))
  "Face for register names in the registers pane."
  :group 'disasm)

(defface disasm-debug-register-changed-face
  '((t :inherit font-lock-warning-face :weight bold))
  "Face marking a register whose value changed at the last stop."
  :group 'disasm)

;;; Data structures

(cl-defstruct (disasm-debug-module (:constructor disasm-debug-module--create))
  "A module loaded in the debugged process."
  path from to main-p)

(cl-defstruct (disasm-debug-frame (:constructor disasm-debug-frame--create))
  "A stack frame of the debugged process."
  level addr func file)

(cl-defstruct (disasm-debug-session (:constructor disasm-debug-session--create))
  "State for one live debugging session."
  backend client
  pid name exe
  (state 'connecting) reason thread
  pc bits arch
  registers flags frames modules entry
  capture capture-active
  listing file delta
  registers-buffer flags-buffer stack-buffer
  breakpoints error)

;;; Helpers

(defun disasm-debug-module-for-address (modules addr)
  "Return the module of MODULES whose range contains ADDR, or nil."
  (cl-find-if (lambda (module)
                (and (>= addr (disasm-debug-module-from module))
                     (< addr (disasm-debug-module-to module))))
              modules))

(defun disasm-debug-session-state-label (session)
  "Return a short human-readable description of SESSION's state."
  (pcase (disasm-debug-session-state session)
    ('connecting "connecting")
    ('stopped "stopped")
    ('running "running")
    ('exited "exited")
    ('detached "detached")
    ('error "error")
    (_ (format "%s" (disasm-debug-session-state session)))))

(defun disasm-debug-flags ()
  "Return the list of (NAME BIT DESCRIPTION) for the x86 flags register."
  '(("CF" 0 "carry")
    ("PF" 2 "parity")
    ("AF" 4 "auxiliary")
    ("ZF" 6 "zero")
    ("SF" 7 "sign")
    ("TF" 8 "trap")
    ("IF" 9 "interrupt")
    ("DF" 10 "direction")
    ("OF" 11 "overflow")))

(defun disasm-debug-flag-set-p (flags name)
  "Return non-nil when flag NAME is set in the integer FLAGS."
  (let ((entry (assoc name (disasm-debug-flags))))
    (and entry (/= 0 (logand flags (ash 1 (nth 1 entry)))))))

(provide 'disasm-debug-core)
;;; disasm-debug-core.el ends here
