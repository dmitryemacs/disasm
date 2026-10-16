;;; disasm-process.el --- External process helpers for disasm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://github.com/dmitryemacs/disasm

;;; Commentary:

;; Thin wrappers around `call-process' and `make-process' shared by the
;; objdump backends, plus output normalization.  objdump on Windows (and
;; llvm-objdump) emit CRLF line endings; everything here normalizes them
;; to plain LF so the parsers can rely on "\n" alone.

;;; Code:

(require 'subr-x)

(defun disasm--normalize-output (output)
  "Normalize OUTPUT by collapsing CRLF (and lone CR) line endings to LF."
  (replace-regexp-in-string "\r\n?" "\n" output))

(defun disasm-process-run (program args)
  "Run PROGRAM with ARGS and return its standard output as a string.
Signal an error when PROGRAM exits with a non-zero status."
  (with-temp-buffer
    (let ((status (apply #'call-process program nil (current-buffer) nil args)))
      (if (and (integerp status) (zerop status))
          (disasm--normalize-output (buffer-string))
        (error "%s failed (status %s):\n%s"
               (file-name-nondirectory program) status
               (string-trim (buffer-string)))))))

(defun disasm-process-run-async (program args callback)
  "Run PROGRAM with ARGS in the background.
Call CALLBACK with two arguments when the process finishes: the exit
STATUS (an integer) and the captured OUTPUT (a string).  Errors that
prevent the process from starting are reported to CALLBACK with a
non-numeric status and an empty output."
  (let ((buffer (generate-new-buffer " *disasm-process*")))
    (condition-case err
        (make-process
         :name "disasm"
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
       (message "disasm: failed to start %s: %s"
                (file-name-nondirectory program) (error-message-string err))
       (funcall callback 'error "")))))

(provide 'disasm-process)
;;; disasm-process.el ends here
