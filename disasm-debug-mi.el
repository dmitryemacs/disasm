;;; disasm-debug-mi.el --- GDB/MI transport and parser for disasm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://github.com/dmitryemacs/disasm

;;; Commentary:

;; A small, self-contained client for the GDB/MI protocol.  It starts a
;; debugger as a subprocess, frames every command with a numeric token so
;; results can be correlated with their request, parses the machine
;; interface grammar (see the GDB manual, "GDB/MI Output Syntax") and
;; hands parsed records to callbacks.
;;
;; A parsed record is a plist:
;;
;;   (:type CHAR :class STRING :data ALIST :text STRING :token INTEGER)
;;
;; CHAR is one of ?^ (result), ?* (exec-async), ?+ (status-async),
;; ?= (notify-async), ?~ (console), ?@ (target), ?& (log).  For tuples
;; the ALIST maps unquoted keys to values; lists are plain Lisp lists
;; whose elements are either strings, alists (nested tuples) or conses
;; (key . value) for named list entries.

;;; Code:

(require 'cl-lib)
(require 'subr-x)

(cl-defstruct (disasm-mi-client (:constructor disasm-mi-client--create))
  "State for a running GDB/MI client."
  process buffer
  (token 0)
  pending
  acc
  on-record
  on-exit)

;;; Value grammar

(defun disasm-mi--skip-blanks (string pos)
  "Return the first non-blank index at or after POS in STRING."
  (while (and (< pos (length string))
              (memq (aref string pos) '(?\s ?\t)))
    (setq pos (1+ pos)))
  pos)

(defun disasm-mi--parse-cstring (string pos)
  "Parse a C string in STRING starting after the opening quote at POS.
Return a cons of the decoded string and the index after the closing quote."
  (let ((out nil)
        (done nil))
    (while (not done)
      (when (>= pos (length string))
        (setq done t))
      (unless done
        (let ((c (aref string pos)))
          (cond
           ((eq c ?\\)
            (let ((n (aref string (1+ pos))))
              (cond
               ((and (>= n ?0) (<= n ?7))
                (let ((value 0)
                      (count 0))
                  (while (and (< count 3)
                              (< (+ pos 1 count) (length string))
                              (let ((d (aref string (+ pos 1 count))))
                                (and (>= d ?0) (<= d ?7))))
                    (setq value (+ (* value 8)
                                   (- (aref string (+ pos 1 count)) ?0)))
                    (setq count (1+ count)))
                  (push (char-to-string value) out)
                  (setq pos (+ pos 1 count))))
               ((eq n ?n) (push "\n" out) (setq pos (+ pos 2)))
               ((eq n ?t) (push "\t" out) (setq pos (+ pos 2)))
               ((eq n ?r) (push "\r" out) (setq pos (+ pos 2)))
               (t (push (char-to-string n) out) (setq pos (+ pos 2))))))
           ((eq c ?\")
            (setq done t)
            (setq pos (1+ pos)))
           (t
            (push (char-to-string c) out)
            (setq pos (1+ pos)))))))
    (cons (apply #'concat (nreverse out)) pos)))

(defun disasm-mi--parse-ident (string pos)
  "Read an unquoted identifier at POS in STRING.
Return a cons of the identifier string and the index after it."
  (let ((start pos))
    (while (and (< pos (length string))
                (let ((c (aref string pos)))
                  (or (and (>= c ?a) (<= c ?z))
                      (and (>= c ?A) (<= c ?Z))
                      (and (>= c ?0) (<= c ?9))
                      (memq c '(?- ?_ ?.)))))
      (setq pos (1+ pos)))
    (cons (substring string start pos) pos)))

(defun disasm-mi--parse-const (string pos)
  "Read an unquoted constant at POS in STRING.
The value ends at a comma, a closing brace/bracket or the end of
STRING.  Return a cons of the (trimmed) string and the index after it."
  (let ((start pos))
    (while (and (< pos (length string))
                (not (memq (aref string pos) '(?, ?} ?\]))))
      (setq pos (1+ pos)))
    (cons (string-trim (substring string start pos)) pos)))

(defun disasm-mi--parse-value (string pos)
  "Parse an MI value in STRING starting at POS.
Return a cons of the value and the index after it: a string for a
constant or a C string, an alist for a tuple, a list for a list."
  (setq pos (disasm-mi--skip-blanks string pos))
  (if (>= pos (length string))
      (cons "" pos)
    (let ((c (aref string pos)))
      (cond
       ((eq c ?{) (disasm-mi--parse-tuple string (1+ pos)))
       ((eq c ?\[) (disasm-mi--parse-list string (1+ pos)))
       ((eq c ?\") (disasm-mi--parse-cstring string (1+ pos)))
       (t (disasm-mi--parse-const string pos))))))

(defun disasm-mi--parse-result (string pos)
  "Parse an MI result (`key=value') or bare value at POS in STRING.
Return a cons of the parsed entry and the index after it.  A named
result is returned as a cons cell (KEY . VALUE)."
  (let* ((key-pos (disasm-mi--parse-ident string pos))
         (key (car key-pos))
         (after (cdr key-pos)))
    (if (and (not (string-empty-p key))
             (< after (length string))
             (eq (aref string after) ?=))
        (let ((value-pos (disasm-mi--parse-value string (1+ after))))
          (cons (cons key (car value-pos)) (cdr value-pos)))
      (disasm-mi--parse-value string pos))))

(defun disasm-mi--parse-tuple (string pos)
  "Parse a tuple in STRING starting after the opening brace at POS."
  (let ((entries nil)
        (done nil))
    (while (not done)
      (setq pos (disasm-mi--skip-blanks string pos))
      (cond
       ((>= pos (length string)) (setq done t))
       ((eq (aref string pos) ?})
        (setq pos (1+ pos))
        (setq done t))
       ((eq (aref string pos) ?,)
        (setq pos (1+ pos)))
       (t
        (let ((entry (disasm-mi--parse-result string pos)))
          (push (car entry) entries)
          (setq pos (cdr entry))))))
    (cons (nreverse entries) pos)))

(defun disasm-mi--parse-list (string pos)
  "Parse a list in STRING starting after the opening bracket at POS."
  (let ((elements nil)
        (done nil))
    (while (not done)
      (setq pos (disasm-mi--skip-blanks string pos))
      (cond
       ((>= pos (length string)) (setq done t))
       ((eq (aref string pos) ?\])
        (setq pos (1+ pos))
        (setq done t))
       ((eq (aref string pos) ?,)
        (setq pos (1+ pos)))
       (t
        (let ((element (disasm-mi--parse-result string pos)))
          (push (car element) elements)
          (setq pos (cdr element))))))
    (cons (nreverse elements) pos)))

(defun disasm-mi--parse-results (string)
  "Parse a comma-separated run of results in STRING into an alist."
  (car (disasm-mi--parse-list (concat "[" string "]") 1)))

;;; Records

(defun disasm-mi--parse-record (type rest)
  "Parse the payload REST of an MI record of TYPE into a plist."
  (if (memq type '(?~ ?@ ?&))
      (let ((value (disasm-mi--parse-value rest 0)))
        (list :type type :text (car value)))
    (if (string-match "\\`\\([A-Za-z][A-Za-z0-9_-]*\\)\\(?:,\\(.*\\)\\)?\\'" rest)
        (let ((class (match-string 1 rest))
              (attrs (match-string 2 rest)))
          (list :type type :class class
                :data (and attrs (disasm-mi--parse-results attrs))))
      (list :type type :class rest))))

(defun disasm-mi-field (alist key)
  "Return the value of KEY in the parsed ALIST, or nil."
  (cdr (assoc key alist)))

;;; Transport

(defun disasm-mi--deliver (client token type rest)
  "Deliver a parsed record to CLIENT.
TOKEN identifies the originating command (nil for asynchronous
records); TYPE is the record type character and REST its payload."
  (let ((record (disasm-mi--parse-record type rest)))
    (if (eq type ?^)
        (let ((entry (assq token (disasm-mi-client-pending client))))
          (when entry
            (setf (disasm-mi-client-pending client)
                  (delq entry (disasm-mi-client-pending client)))
            (funcall (cdr entry) record)))
      (let ((handler (disasm-mi-client-on-record client)))
        (when handler
          (funcall handler record token))))))

(defun disasm-mi--dispatch (client line)
  "Parse and deliver a single complete LINE received by CLIENT."
  (cond
   ((string-empty-p line) nil)
   ((string-prefix-p "(gdb)" line) nil)
   ((string-match "\\`\\([0-9]+\\)\\([\\^\\*\\+=~@&]\\)\\(.*\\)\\'" line)
    (disasm-mi--deliver client
                        (string-to-number (match-string 1 line))
                        (aref line (match-beginning 2))
                        (match-string 3 line)))
   ((string-match "\\`\\([\\^\\*\\+=~@&]\\)\\(.*\\)\\'" line)
    (disasm-mi--deliver client nil
                        (aref line (match-beginning 1))
                        (match-string 2 line)))
   (t nil)))

(defun disasm-mi--filter (client chunk)
  "Feed the CHUNK of output received by CLIENT through the parser."
  (let* ((text (concat (or (disasm-mi-client-acc client) "") chunk))
         (lines (split-string text "\n")))
    (setf (disasm-mi-client-acc client) (car (last lines)))
    (dolist (line (butlast lines))
      (disasm-mi--dispatch client (string-trim-right line "\r")))))

(defun disasm-mi-start (program args on-record &optional on-exit)
  "Start PROGRAM with ARGS as an MI client.
ON-RECORD is called with each asynchronous record and its token;
ON-EXIT is called with the exit status when the process ends.  Return
the new `disasm-mi-client'."
  (let* ((buffer (generate-new-buffer " *disasm-mi*"))
         (client (disasm-mi-client--create
                  :buffer buffer
                  :acc ""
                  :on-record on-record
                  :on-exit on-exit)))
    (setf (disasm-mi-client-process client)
          (make-process
           :name "disasm-mi"
           :buffer buffer
           :command (cons program args)
           :coding 'utf-8-unix
           :noquery t
           :connection-type 'pipe
           :filter (lambda (_process chunk)
                     (disasm-mi--filter client chunk))
           :sentinel (lambda (process _event)
                       (when (memq (process-status process) '(exit signal))
                         (let ((handler (disasm-mi-client-on-exit client)))
                           (when handler
                             (funcall handler (process-exit-status process))))))))
    client))

(defun disasm-mi-send (client command callback)
  "Send COMMAND to CLIENT and call CALLBACK with the result record.
Return the numeric token used to frame COMMAND."
  (let ((token (cl-incf (disasm-mi-client-token client))))
    (push (cons token callback) (disasm-mi-client-pending client))
    (process-send-string (disasm-mi-client-process client)
                         (format "%d%s\n" token command))
    token))

(defun disasm-mi-send-ignore (client command)
  "Send COMMAND to CLIENT and ignore the result."
  (disasm-mi-send client command #'ignore))

(defun disasm-mi-exec (client command callback)
  "Run the CLI COMMAND inside CLIENT and pass its output to CALLBACK."
  (disasm-mi-send
   client
   (format "-interpreter-exec console \"%s\""
           (replace-regexp-in-string "\"" "\\\\\"" command))
   callback))

(defun disasm-mi--quit (client)
  "Stop CLIENT's process, if it is still running."
  (let ((process (disasm-mi-client-process client)))
    (when (and process (process-live-p process))
      (ignore-errors (delete-process process))))
  (let ((buffer (disasm-mi-client-buffer client)))
    (when (buffer-live-p buffer)
      (ignore-errors (kill-buffer buffer)))))

(provide 'disasm-debug-mi)
;;; disasm-debug-mi.el ends here
