;;; disasm-proc.el --- Process enumeration for disasm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://github.com/dmitryemacs/disasm

;;; Commentary:

;; Lists the running processes so the user can pick one to attach a
;; debugger to.  The implementation is platform specific: on Windows we
;; parse `tasklist' CSV output, elsewhere we use `ps'.  Only the process
;; id and image name are collected here; the full image path is obtained
;; later from GDB's `info files' output.

;;; Code:

(require 'cl-lib)
(require 'subr-x)
(require 'disasm-process)

(cl-defstruct (disasm-proc-entry (:constructor disasm-proc-entry--create))
  "A running process."
  pid name)

(defun disasm-proc--split-csv-line (line)
  "Split a single CSV LINE into a list of unquoted fields."
  (let ((fields nil)
        (current nil)
        (in-quotes nil)
        (i 0)
        (n (length line)))
    (while (< i n)
      (let ((c (aref line i)))
        (cond
         (in-quotes
          (if (eq c ?\")
              (if (and (< (1+ i) n) (eq (aref line (1+ i)) ?\"))
                  (progn (push ?\" current) (setq i (+ i 2)))
                (setq in-quotes nil)
                (setq i (1+ i)))
            (push c current)
            (setq i (1+ i))))
         ((eq c ?\")
          (setq in-quotes t)
          (setq i (1+ i)))
         ((eq c ?,)
          (push (apply #'string (nreverse current)) fields)
          (setq current nil)
          (setq i (1+ i)))
         (t
          (push c current)
          (setq i (1+ i))))))
    (push (apply #'string (nreverse current)) fields)
    (nreverse fields)))

(defun disasm-proc--list-windows ()
  "Return the running processes on Windows as `disasm-proc-entry' objects."
  (let ((output (disasm-process-run "tasklist.exe" '("/fo" "csv" "/nh"))))
    (delq nil
          (mapcar
           (lambda (line)
             (let ((fields (disasm-proc--split-csv-line line)))
               (when (and (>= (length fields) 2)
                          (string-match-p "\\`[0-9]+\\'" (nth 1 fields)))
                 (disasm-proc-entry--create
                  :pid (string-to-number (nth 1 fields))
                  :name (nth 0 fields)))))
           (split-string output "\n" t)))))

(defun disasm-proc--list-posix ()
  "Return the running processes on POSIX systems."
  (let ((output (disasm-process-run "ps" '("-eo" "pid=,comm="))))
    (delq nil
          (mapcar
           (lambda (line)
             (when (string-match "\\`[ \t]*\\([0-9]+\\)[ \t]+\\(.+\\)\\'" line)
               (disasm-proc-entry--create
                :pid (string-to-number (match-string 1 line))
                :name (string-trim (match-string 2 line)))))
           (split-string output "\n" t)))))

(defun disasm-proc-list ()
  "Return the running processes as a list of `disasm-proc-entry' objects."
  (if (eq system-type 'windows-nt)
      (disasm-proc--list-windows)
    (disasm-proc--list-posix)))

(defun disasm-proc--format (entry)
  "Return a one-line description of ENTRY for the minibuffer."
  (format "%-6d %s" (disasm-proc-entry-pid entry) (disasm-proc-entry-name entry)))

(defun disasm-proc-read ()
  "Prompt the user for a running process and return its entry."
  (let* ((entries (disasm-proc-list))
         (table (mapcar (lambda (entry)
                          (cons (disasm-proc--format entry) entry))
                        entries)))
    (unless entries
      (user-error "Could not list any running processes"))
    (cdr (assoc (completing-read "Attach to process: " table nil t) table))))

(provide 'disasm-proc)
;;; disasm-proc.el ends here
