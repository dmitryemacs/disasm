;;; disasm-cache.el --- In-memory result cache for disasm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://example.invalid/disasm

;;; Commentary:

;; A small in-memory cache of parsed disassembly results, keyed by the
;; file's identity (path, size, modification time) together with the
;; active backend and options.  It makes re-opening a file, and toggling
;; options such as \"all sections\", instant instead of re-running
;; objdump.  Entries are invalidated automatically because the key
;; includes the file's size and mtime.

;;; Code:

(require 'cl-lib)
(require 'subr-x)
(require 'disasm-core)

(defcustom disasm-cache-enabled t
  "When non-nil, cache parsed disassembly results in memory."
  :type 'boolean
  :group 'disasm)

(defcustom disasm-cache-max-entries 8
  "Maximum number of cached disassembly results to keep."
  :type 'integer
  :group 'disasm)

(defvar disasm--cache (make-hash-table :test #'equal)
  "Hash table mapping cache keys to parsed disassembly plists.")

(defvar disasm--cache-order nil
  "List of cache keys in insertion order, oldest first.")

(defun disasm-cache-key (file raw all-sections)
  "Return the cache key for FILE disassembled with RAW and ALL-SECTIONS.
The key incorporates the file's size and modification time so that a
changed file never yields a stale hit, plus the options that affect the
objdump output."
  (let ((attrs (file-attributes file)))
    (list (expand-file-name file)
          (and attrs (file-attribute-size attrs))
          (and attrs (file-attribute-modification-time attrs))
          disasm-backend disasm-syntax disasm-demangle
          disasm-objdump-extra-args disasm-llvm-objdump-extra-args
          all-sections raw)))

(defun disasm-cache-get (key)
  "Return the cached value for KEY, or nil."
  (when disasm-cache-enabled
    (gethash key disasm--cache)))

(defun disasm-cache-put (key value)
  "Store VALUE under KEY, evicting the oldest entries when over the limit."
  (when disasm-cache-enabled
    (unless (gethash key disasm--cache)
      (setq disasm--cache-order (append disasm--cache-order (list key))))
    (puthash key value disasm--cache)
    (while (and (> (length disasm--cache-order) disasm-cache-max-entries)
                disasm--cache-order)
      (remhash (car disasm--cache-order) disasm--cache)
      (setq disasm--cache-order (cdr disasm--cache-order)))
    value))

(defun disasm-cache-clear ()
  "Forget all cached disassembly results."
  (interactive)
  (clrhash disasm--cache)
  (setq disasm--cache-order nil)
  (when (called-interactively-p 'interactive)
    (message "disasm: cache cleared")))

(provide 'disasm-cache)
;;; disasm-cache.el ends here
