;;; disasm-debug-gdb.el --- GDB/MI debugging backend for disasm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://github.com/dmitryemacs/disasm

;;; Commentary:

;; The GDB backend of the `disasm' debugger.  It drives a GDB process
;; through the machine interface (see `disasm-debug-mi') and translates
;; its answers into the backend-neutral `disasm-debug-session' state:
;; registers and flags are read from `info registers' (which also decodes
;; the flags word), the call stack from `-stack-list-frames' and the list
;; of loaded modules together with the image path and entry point from
;; `info files'.

;;; Code:

(require 'cl-lib)
(require 'subr-x)
(require 'disasm-core)
(require 'disasm-debug-core)
(require 'disasm-debug-mi)
(require 'disasm-debug-win)

(declare-function disasm-debug--ui-refresh "disasm-debug" (session))
(declare-function disasm-debug--on-exit "disasm-debug" (session status))
(declare-function disasm-debug--rename-listing "disasm-debug" (session))

(defconst disasm-debug-gdb--register-names-64
  '("rax" "rbx" "rcx" "rdx" "rsi" "rdi" "rbp" "rsp"
    "r8" "r9" "r10" "r11" "r12" "r13" "r14" "r15" "rip")
  "General purpose register names shown for 64-bit targets.")

(defconst disasm-debug-gdb--register-names-32
  '("eax" "ebx" "ecx" "edx" "esi" "edi" "ebp" "esp" "eip")
  "General purpose register names shown for 32-bit targets.")

;;; Program detection

(defun disasm-debug-gdb--resolve-program ()
  "Return the path of the GDB executable to use."
  (or (and disasm-debug-program
           (or (executable-find disasm-debug-program)
               disasm-debug-program))
      (cl-loop for candidate in '("D:/Qt/Tools/mingw1310_64/bin/gdb.exe"
                                  "C:/msys64/mingw64/bin/gdb.exe"
                                  "C:/msys64/usr/bin/gdb.exe"
                                  "C:/cygwin64/bin/gdb.exe"
                                  "gdb")
               for found = (executable-find candidate)
               when found return found)
      (user-error "gdb not found; customize `disasm-debug-program'")))

;;; Parsing helper output

(defun disasm-debug-gdb--parse-registers (text)
  "Parse the output TEXT of `info registers'.
Return a list (REGISTERS FLAGS) where REGISTERS is an alist mapping
register names to their hexadecimal value strings and FLAGS is the
integer value of the flags register (or nil)."
  (let ((registers nil)
        (flags nil))
    (dolist (line (split-string text "\n"))
      (when (string-match "\\`[ \t]*\\([a-z][a-z0-9]*\\)[ \t]+\\(0x[0-9a-fA-F]+\\)" line)
        (let ((name (match-string 1 line))
              (value (match-string 2 line)))
          (push (cons name value) registers)
          (when (equal name "eflags")
            (setq flags (disasm--hex-to-int value))))))
    (list (nreverse registers) flags)))

(defun disasm-debug-gdb--parse-info-files (text)
  "Parse the output TEXT of `info files'.
Return a plist with :main (image path), :entry (integer), :bits and
:modules (a list of `disasm-debug-module')."
  (let ((main nil)
        (entry nil)
        (bits nil)
        (module-alist nil)
        (order nil))
    (dolist (line (split-string text "\n"))
      (cond
       ((string-match "`\\(.+?\\)', file type \\([^ \n]+\\)" line)
        (setq main (match-string 1 line))
        (setq bits (if (string-match-p "64" (match-string 2 line)) 64 32)))
       ((string-match "Entry point: \\(0x[0-9a-fA-F]+\\)" line)
        (setq entry (disasm--hex-to-int (match-string 1 line))))
       ((string-match "\\`[ \t]*\\(0x[0-9a-fA-F]+\\) - \\(0x[0-9a-fA-F]+\\) is [^ \n]+\\(?: in \\(.+\\)\\)?\\'" line)
        (let* ((from (disasm--hex-to-int (match-string 1 line)))
               (to (disasm--hex-to-int (match-string 2 line)))
               (path (or (match-string 3 line) main))
               (cell (assoc path module-alist)))
          (if cell
              (setf (nth 1 cell) (min (nth 1 cell) from)
                    (nth 2 cell) (max (nth 2 cell) to))
            (push (list path from to) module-alist)
            (push path order))))))
    (list :main main :entry entry :bits bits
          :modules
          (mapcar (lambda (path)
                    (let ((cell (assoc path module-alist)))
                      (disasm-debug-module--create
                       :path (nth 0 cell)
                       :from (nth 1 cell)
                       :to (nth 2 cell)
                       :main-p (and main (equal path main)))))
                  (nreverse order)))))

(defun disasm-debug-gdb--frames-from-record (record)
  "Extract the stack frames from a `-stack-list-frames' RECORD."
  (let ((stack (disasm-mi-field (plist-get record :data) "stack")))
    (mapcar
     (lambda (frame)
       (disasm-debug-frame--create
        :level (string-to-number (or (disasm-mi-field frame "level") "0"))
        :addr (let ((addr (disasm-mi-field frame "addr")))
                (and addr (disasm--hex-to-int addr)))
        :func (disasm-mi-field frame "func")
        :file (disasm-mi-field frame "from")))
     stack)))

(defun disasm-debug-gdb--memory-from-record (record)
  "Return the bytes carried by a `-data-read-memory-bytes' RECORD, or nil."
  (when (equal (plist-get record :class) "done")
    (let ((memory (disasm-mi-field (plist-get record :data) "memory")))
      (when memory
        (apply #'concat
               (mapcar (lambda (chunk)
                         (disasm--hex-string-to-unibyte
                          (or (disasm-mi-field chunk "contents") "")))
                       memory))))))

(defun disasm-debug-gdb--breakpoint (bkpt)
  "Build a `disasm-debug-breakpoint' from a parsed MI BKPT tuple."
  (when bkpt
    (disasm-debug-breakpoint--create
     :number (string-to-number (or (disasm-mi-field bkpt "number") "0"))
     :addr (let ((addr (disasm-mi-field bkpt "addr")))
             (and addr (disasm--hex-to-int addr)))
     :enabled (not (equal (disasm-mi-field bkpt "enabled") "n"))
     :func (disasm-mi-field bkpt "func")
     :file (disasm-mi-field bkpt "file")
     :line (let ((line (disasm-mi-field bkpt "line")))
             (and line (string-to-number line))))))

(defun disasm-debug-gdb--breakpoint-from-record (record)
  "Return the `disasm-debug-breakpoint' described by an insert RECORD, or nil."
  (disasm-debug-gdb--breakpoint (disasm-mi-field (plist-get record :data) "bkpt")))

(defun disasm-debug-gdb--breakpoints-from-record (record)
  "Return the list of breakpoints described by a `-break-list' RECORD."
  (let* ((table (disasm-mi-field (plist-get record :data) "BreakpointTable"))
         (body (and table (disasm-mi-field table "body"))))
    (delq nil (mapcar (lambda (entry)
                        (disasm-debug-gdb--breakpoint
                         (if (consp entry) (cdr entry) entry)))
                      (or body (disasm-mi-field table "bkpt"))))))

;;; Records

(defun disasm-debug-gdb--on-record (session record _token)
  "Update SESSION from the asynchronous MI RECORD."
  (let ((type (plist-get record :type)))
    (cond
     ((and (disasm-debug-session-capture-active session)
           (eq type ?~))
      (setf (disasm-debug-session-capture session)
            (concat (disasm-debug-session-capture session)
                    (or (plist-get record :text) ""))))
     ((eq type ?=)
      (pcase (plist-get record :class)
        ("thread-group-started"
         (let ((pid (disasm-mi-field (plist-get record :data) "pid")))
           (when (and pid (null (disasm-debug-session-pid session)))
             (setf (disasm-debug-session-pid session) (string-to-number pid))
             (disasm-debug--rename-listing session))))))
     ((eq type ?*)
      (pcase (plist-get record :class)
        ("stopped"
         (let* ((data (plist-get record :data))
                (reason (disasm-mi-field data "reason"))
                (bkptno (disasm-mi-field data "bkptno")))
           (setf (disasm-debug-session-reason session) reason)
           (setf (disasm-debug-session-hit-breakpoint session)
                 (and bkptno (string-to-number bkptno)))
           (setf (disasm-debug-session-state session)
                 (if (and reason (string-prefix-p "exited" reason))
                     'exited
                   'stopped))
           (disasm-debug-gdb-refresh session)))
        ("running"
         (setf (disasm-debug-session-state session) 'running)
         (disasm-debug--ui-refresh session)))))))

;;; Commands

(defun disasm-debug-gdb--send (session command &optional callback)
  "Send COMMAND to SESSION's debugger, reporting errors by message.
CALLBACK is called with the result record when supplied."
  (disasm-mi-send (disasm-debug-session-client session)
                  command
                  (or callback
                      (lambda (record)
                        (unless (member (plist-get record :class)
                                        '("done" "running"))
                          (message "disasm: %s"
                                   (or (disasm-mi-field (plist-get record :data) "msg")
                                       "command failed")))))))

(defun disasm-debug-gdb--console (session command callback)
  "Run the CLI COMMAND and collect its textual output.
Call CALLBACK with the captured text and the final record."
  (setf (disasm-debug-session-capture-active session) t)
  (setf (disasm-debug-session-capture session) "")
  (disasm-mi-exec
   (disasm-debug-session-client session)
   command
   (lambda (record)
     (setf (disasm-debug-session-capture-active session) nil)
     (let ((text (disasm-debug-session-capture session)))
       (setf (disasm-debug-session-capture session) "")
       (funcall callback text record)))))

(defun disasm-debug-gdb-start (session)
  "Start a GDB process for SESSION and configure it."
  (let ((program (disasm-debug-gdb--resolve-program)))
    (setf (disasm-debug-session-client session)
          (disasm-mi-start
           program
           (list "-q" "--interpreter=mi2")
           (lambda (record token) (disasm-debug-gdb--on-record session record token))
           (lambda (status) (disasm-debug--on-exit session status))))
    (let ((client (disasm-debug-session-client session)))
      (dolist (setting '("-gdb-set pagination off"
                         "-gdb-set confirm off"
                         "-gdb-set mi-async on"
                         "-gdb-set width 0"
                         "-gdb-set height 0"
                         "-gdb-set print pretty off"
                         "-gdb-set disassembly-flavor intel"
                         "-gdb-set new-console off"))
        (disasm-mi-send-ignore client setting)))))

(defun disasm-debug-gdb-attach (session pid)
  "Attach SESSION's debugger to the process PID."
  (disasm-mi-send
   (disasm-debug-session-client session)
   (format "-target-attach %d" pid)
   (lambda (record)
     (if (equal (plist-get record :class) "done")
         (when (eq (disasm-debug-session-state session) 'connecting)
           (setf (disasm-debug-session-state session) 'stopped)
           (disasm-debug-gdb-refresh session))
       (setf (disasm-debug-session-state session) 'error)
       (setf (disasm-debug-session-error session)
             (or (disasm-mi-field (plist-get record :data) "msg") "attach failed"))
       (disasm-debug--ui-refresh session)))))

(defun disasm-debug-gdb-detach (session)
  "Detach SESSION's debugger from its target and quit GDB."
  (let ((client (disasm-debug-session-client session)))
    (when (and client (process-live-p (disasm-mi-client-process client)))
      (disasm-mi-send
       client "-target-detach"
       (lambda (_record)
         (disasm-mi-send-ignore client "-gdb-exit")))
      (run-at-time
       2 nil
       (lambda ()
         (when (and client (process-live-p (disasm-mi-client-process client)))
           (disasm-mi--quit client)))))))

;;; State refresh

(defun disasm-debug-gdb-refresh (session)
  "Query SESSION's registers, modules and stack, then refresh the UI."
  (when (disasm-debug-session-client session)
    (disasm-debug-gdb--console
     session "info registers"
     (lambda (text _record)
       (pcase-let ((`(,registers ,flags)
                    (disasm-debug-gdb--parse-registers text)))
         (setf (disasm-debug-session-registers session) registers)
         (setf (disasm-debug-session-flags session) flags))
       (disasm-debug-gdb--refresh-modules session)))))

(defun disasm-debug-gdb--refresh-modules (session)
  "Read the loaded modules for SESSION, then continue refreshing."
  (disasm-debug-gdb--console
   session "info files"
   (lambda (text _record)
     (let ((info (disasm-debug-gdb--parse-info-files text)))
       (setf (disasm-debug-session-modules session) (plist-get info :modules))
       (setf (disasm-debug-session-entry session) (plist-get info :entry))
       (when (plist-get info :main)
         (setf (disasm-debug-session-exe session) (plist-get info :main)))
       (when (plist-get info :bits)
         (setf (disasm-debug-session-bits session) (plist-get info :bits))))
     (disasm-debug-gdb--refresh-frames session))))

(defun disasm-debug-gdb--refresh-frames (session)
  "Read the stack of SESSION, then refresh the UI."
  (disasm-mi-send
   (disasm-debug-session-client session)
   "-stack-list-frames"
   (lambda (record)
     (let ((frames (disasm-debug-gdb--frames-from-record record)))
       (setf (disasm-debug-session-frames session) frames)
       (let ((frame (car frames)))
         (when frame
           (setf (disasm-debug-session-pc session) (disasm-debug-frame-addr frame)))))
     (disasm-debug--ui-refresh session))))

;;; Launch

(defun disasm-debug-gdb--quote (string)
  "Quote STRING as a single MI C-string argument.
Backslashes and double quotes are escaped with a backslash, so that the
MI parser recovers STRING unchanged."
  (concat "\""
          (mapconcat (lambda (char)
                       (cond ((eq char ?\\) "\\\\")
                             ((eq char ?\") "\\\"")
                             (t (char-to-string char))))
                     (or string "") "")
          "\""))

(defun disasm-debug-gdb-load (session file)
  "Point SESSION's debugger at the executable FILE."
  (disasm-debug-gdb--send
   session
   (format "-file-exec-and-symbols %s" (disasm--file-arg file))))

(defun disasm-debug-gdb-set-directory (session directory)
  "Make DIRECTORY the working directory of SESSION's target."
  (disasm-debug-gdb--send
   session
   (format "-environment-cd %s" (disasm-debug-gdb--quote directory))))

(defun disasm-debug-gdb-set-arguments (session arguments)
  "Set the arguments used when SESSION's target is run to ARGUMENTS."
  (disasm-debug-gdb--send
   session
   (format "-exec-arguments %s" (disasm-debug-gdb--quote arguments))))

(defun disasm-debug-gdb-run (session)
  "Launch SESSION's target and stop at its entry.
GDB on Windows does not stop at the program entry after a plain
`-exec-run', so we first plant a temporary breakpoint at `main' and run;
when no `main' symbol is available we fall back to `starti', which stops
at the first instruction of the program."
  (disasm-mi-send
   (disasm-debug-session-client session)
   "-break-insert -t main"
   (lambda (record)
     (if (equal (plist-get record :class) "done")
         (disasm-debug-gdb--send session "-exec-run")
       (disasm-debug-gdb--send session "-interpreter-exec console \"starti\"")))))

;;; Breakpoints

(defun disasm-debug-gdb-break-insert (session address callback)
  "Insert a breakpoint at the live ADDRESS for SESSION.
Call CALLBACK with the resulting `disasm-debug-breakpoint', or nil when
the breakpoint could not be inserted."
  (if (null address)
      (progn (message "disasm: no address to set a breakpoint at")
             (funcall callback nil))
    (disasm-mi-send
     (disasm-debug-session-client session)
     (format "-break-insert *0x%x" address)
     (lambda (record)
       (if (equal (plist-get record :class) "done")
           (funcall callback (disasm-debug-gdb--breakpoint-from-record record))
         (message "disasm: cannot set a breakpoint at 0x%x: %s" address
                  (or (disasm-mi-field (plist-get record :data) "msg") "failed"))
         (funcall callback nil))))))

(defun disasm-debug-gdb-break-delete (session number &optional callback)
  "Delete the breakpoint NUMBER from SESSION's debugger."
  (disasm-mi-send
   (disasm-debug-session-client session)
   (format "-break-delete %d" number)
   (lambda (record)
     (unless (equal (plist-get record :class) "done")
       (message "disasm: cannot delete breakpoint %d: %s" number
                (or (disasm-mi-field (plist-get record :data) "msg") "failed")))
     (when callback (funcall callback (equal (plist-get record :class) "done"))))))

(defun disasm-debug-gdb-break-list (session)
  "Return the breakpoints currently set in SESSION's debugger.
This performs a synchronous round trip and therefore requires the target
to be stopped."
  (disasm-debug-gdb--breakpoints-from-record
   (disasm-mi-request (disasm-debug-session-client session) "-break-list")))

;;; Editing

(defun disasm-debug-gdb-write-register (session name value &optional callback)
  "Write VALUE to the register NAME of SESSION's target.
Call CALLBACK with non-nil on success.  The target must be stopped."
  (disasm-mi-send
   (disasm-debug-session-client session)
   (format "-gdb-set $%s = 0x%x" name value)
   (lambda (record)
     (let ((ok (equal (plist-get record :class) "done")))
       (unless ok
         (message "disasm: cannot set $%s: %s" name
                  (or (disasm-mi-field (plist-get record :data) "msg") "failed")))
       (when callback (funcall callback ok))))))

(defun disasm-debug-gdb-write-memory (session address bytes &optional callback)
  "Write BYTES, a unibyte string, at the live ADDRESS of SESSION's target.
Call CALLBACK with non-nil on success.  The target must be stopped."
  (disasm-mi-send
   (disasm-debug-session-client session)
   (format "-data-write-memory-bytes 0x%x %s"
           address (disasm--unibyte-to-hex bytes))
   (lambda (record)
     (let ((ok (equal (plist-get record :class) "done")))
       (unless ok
         (message "disasm: cannot write memory at 0x%x: %s" address
                  (or (disasm-mi-field (plist-get record :data) "msg") "failed")))
       (when callback (funcall callback ok))))))

;;; Execution control

(defun disasm-debug-gdb-continue (session)
  "Resume SESSION's target."
  (disasm-debug-gdb--send session "-exec-continue"))

(defun disasm-debug-gdb-stepi (session)
  "Step one instruction in SESSION's target."
  (disasm-debug-gdb--send session "-exec-step-instruction"))

(defun disasm-debug-gdb-nexti (session)
  "Step over one instruction in SESSION's target."
  (disasm-debug-gdb--send session "-exec-next-instruction"))

(defun disasm-debug-gdb-finish (session)
  "Run SESSION's target until the current function returns."
  (disasm-debug-gdb--send session "-exec-finish"))

(defun disasm-debug-gdb--interrupt-windows (session)
  "Interrupt SESSION's running target on Windows.
GDB does not read its standard input while the inferior runs, so
`-exec-interrupt' is useless here.  We instead ask the kernel to inject a
breakpoint into the target with `DebugBreakProcess'; GDB, being attached,
observes it and stops.  When the helper is unavailable, fall back to
signalling the target with `SIGINT' and finally to `-exec-interrupt'."
  (let ((pid (disasm-debug-session-pid session)))
    (cond
     ((and pid (disasm-debug-win-break-process pid)) nil)
     ((and pid (ignore-errors (zerop (signal-process pid 'SIGINT)))) nil)
     (t (disasm-debug-gdb--send session "-exec-interrupt")))))

(defun disasm-debug-gdb-interrupt (session)
  "Interrupt SESSION's target."
  (if (eq (disasm-debug-session-state session) 'running)
      (if (eq system-type 'windows-nt)
          (disasm-debug-gdb--interrupt-windows session)
        (disasm-debug-gdb--send session "-exec-interrupt"))
    (message "disasm: the target is not running")))

;;; Live memory

(defun disasm-debug-gdb-read-memory (session address length)
  "Read LENGTH bytes of SESSION's target memory at live ADDRESS.
Return a unibyte string, or nil when the memory cannot be read.  The
target must be stopped, otherwise the request is not answered."
  (when (and (> length 0)
             (disasm-debug-session-client session))
    (disasm-debug-gdb--memory-from-record
     (disasm-mi-request
      (disasm-debug-session-client session)
      (format "-data-read-memory-bytes 0x%x %d" address length)))))

(provide 'disasm-debug-gdb)
;;; disasm-debug-gdb.el ends here
