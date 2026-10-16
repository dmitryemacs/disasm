;;; disasm-backend.el --- Backend dispatch for disasm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://github.com/dmitryemacs/disasm

;;; Commentary:

;; Dispatches the backend-neutral operations (read header, read sections,
;; disassemble) to the implementation selected by `disasm-backend'.  The
;; two implementations live in `disasm-objdump' (GNU) and `disasm-llvm'.

;;; Code:

(require 'disasm-core)
(require 'disasm-objdump)
(require 'disasm-llvm)

(defun disasm-backend-name ()
  "Return a human-readable name for the current backend."
  (pcase disasm-backend
    ('objdump "objdump")
    ('llvm-objdump "llvm-objdump")
    (_ (format "%s" disasm-backend))))

(defun disasm-backend-supports-raw-p ()
  "Return non-nil when the current backend can disassemble raw binaries."
  (eq disasm-backend 'objdump))

(defun disasm-backend-program ()
  "Return the executable path used by the current backend."
  (pcase disasm-backend
    ('objdump (disasm-objdump--resolve-program))
    ('llvm-objdump (disasm-llvm--resolve-program))
    (_ (user-error "Unknown disasm backend: %s" disasm-backend))))

(defun disasm-backend-header (file &optional raw)
  "Return the parsed header of FILE for the current backend.
RAW has the same meaning as in `disasm-objdump-header'."
  (pcase disasm-backend
    ('objdump (disasm-objdump-header file raw))
    ('llvm-objdump (disasm-llvm-header file raw))
    (_ (user-error "Unknown disasm backend: %s" disasm-backend))))

(defun disasm-backend-sections (file &optional raw)
  "Return the sections of FILE for the current backend.
RAW has the same meaning as in `disasm-objdump-sections'."
  (pcase disasm-backend
    ('objdump (disasm-objdump-sections file raw))
    ('llvm-objdump (disasm-llvm-sections file raw))
    (_ (user-error "Unknown disasm backend: %s" disasm-backend))))

(defun disasm-backend-disassemble (file sections all-sections &optional raw)
  "Disassemble FILE synchronously for the current backend.
SECTIONS, ALL-SECTIONS and RAW are as in `disasm-objdump-disassemble'."
  (pcase disasm-backend
    ('objdump (disasm-objdump-disassemble file sections all-sections raw))
    ('llvm-objdump (disasm-llvm-disassemble file sections all-sections raw))
    (_ (user-error "Unknown disasm backend: %s" disasm-backend))))

(defun disasm-backend-disassemble-async (file sections all-sections raw callback)
  "Disassemble FILE asynchronously for the current backend.
SECTIONS, ALL-SECTIONS, RAW and CALLBACK are as in
`disasm-objdump-disassemble-async'."
  (pcase disasm-backend
    ('objdump
     (disasm-objdump-disassemble-async file sections all-sections raw callback))
    ('llvm-objdump
     (disasm-llvm-disassemble-async file sections all-sections raw callback))
    (_ (user-error "Unknown disasm backend: %s" disasm-backend))))

(provide 'disasm-backend)
;;; disasm-backend.el ends here
