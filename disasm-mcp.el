;;; disasm-mcp.el --- MCP endpoint for the disasm debugger  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://github.com/dmitryemacs/disasm

;;; Commentary:

;; This file turns the running debugger into something an external agent
;; can drive.  It opens a small TCP listener on the loopback interface,
;; speaks a line-delimited JSON request/response protocol on it and
;; translates every request into a call of the ordinary `disasm'
;; functions.  Because the same functions are used, everything an agent
;; does shows up in the usual panes, the listing and the hex view; the
;; `*disasm-agent*' buffer keeps a running log of the traffic so the user
;; can watch the agent work.
;;
;; The companion MCP server (mcp/disasm-mcp-server.mjs, run by the agent
;; host) connects to this listener and exposes the operations as Model
;; Context Protocol tools.  See mcp/README.md for the wiring.
;;
;; Protocol
;; --------
;; One JSON object per line, in both directions.  A request looks like
;;
;;   {"id": 7, "token": "…", "op": "state", "args": {"session": "1234"}}
;;
;; and is answered by exactly one line
;;
;;   {"id": 7, "ok": true, "result": {…}}
;;   {"id": 7, "ok": false, "error": "…", "kind": "user-error"}
;;
;; The token is generated when the server starts and written to
;; `disasm-mcp-token-file'; requests carrying the wrong token are
;; refused, so no other local process can drive the debugger.

;;; Code:

(require 'cl-lib)
(require 'subr-x)
(require 'json)
(require 'disasm-core)
(require 'disasm-debug-core)
(require 'disasm-debug)

(declare-function disasm-file "disasm" (file))
(declare-function disasm-debug-run "disasm-debug" (file arguments))
(declare-function disasm-attach "disasm-debug" (entry))
(declare-function disasm-proc-entry--create "disasm-proc" (&key pid name))

;;; Customization

(defgroup disasm-mcp nil
  "Model Context Protocol access to the disasm debugger."
  :group 'disasm)

(defcustom disasm-mcp-auto-start t
  "Whether to start the MCP listener when `disasm' is loaded.
The listener only accepts connections from the loopback interface and
requires the token from `disasm-mcp-token-file', so leaving it on is
safe on a single-user machine."
  :type 'boolean
  :group 'disasm-mcp)

(defcustom disasm-mcp-host "127.0.0.1"
  "Address the MCP listener binds to.
Leave it on the loopback interface unless you know what you are doing."
  :type 'string
  :group 'disasm-mcp)

(defcustom disasm-mcp-port 37373
  "TCP port the MCP listener binds to."
  :type 'integer
  :group 'disasm-mcp)

(defcustom disasm-mcp-token-file nil
  "File the listener writes its access token to.
The MCP server reads the token from there.  When nil, a file named
`disasm-mcp-token' is used inside `user-emacs-directory'."
  :type '(choice (const :tag "Default" nil) file)
  :group 'disasm-mcp)

(defcustom disasm-mcp-follow-agent t
  "Whether an agent's memory reads move the visible listing.
When non-nil, requests that look inside the target (disassembly and
memory reads) also scroll the listing and the hex pane to the address
they examine, so the user can see where the agent is looking.  Set it
to nil to leave the user's view alone."
  :type 'boolean
  :group 'disasm-mcp)

(defcustom disasm-mcp-log-limit 500
  "Maximum number of entries kept in the `*disasm-agent*' log."
  :type 'integer
  :group 'disasm-mcp)

(defconst disasm-mcp-version "0.1.0"
  "Version of the MCP endpoint.")

(defconst disasm-mcp-protocol 1
  "Version of the wire protocol spoken by the MCP endpoint.")

;;; Faces

(defface disasm-mcp-log-op-face
  '((t :inherit font-lock-function-name-face))
  "Face for the operation name in the agent log."
  :group 'disasm-mcp)

(defface disasm-mcp-log-args-face
  '((t :inherit shadow))
  "Face for the arguments of a logged request."
  :group 'disasm-mcp)

(defface disasm-mcp-log-ok-face
  '((t :inherit success))
  "Face for the outcome of a successful request."
  :group 'disasm-mcp)

(defface disasm-mcp-log-error-face
  '((t :inherit error :weight bold))
  "Face for the outcome of a failed request."
  :group 'disasm-mcp)

(defface disasm-mcp-log-event-face
  '((t :inherit font-lock-keyword-face))
  "Face for debugger events in the agent log."
  :group 'disasm-mcp)

(defface disasm-mcp-log-detail-face
  '((t :inherit shadow))
  "Face for the expandable detail line of a log entry."
  :group 'disasm-mcp)

;;; State

(defvar disasm-mcp--server-process nil
  "The listening socket of the MCP endpoint, or nil.")

(defvar disasm-mcp--port nil
  "Port the listener actually bound, once it is running.")

(defvar disasm-mcp--clients nil
  "List of connections currently open on the MCP endpoint.")

(defvar disasm-mcp--token nil
  "Access token expected in every request.")

(defvar disasm-mcp--queue nil
  "Requests waiting to be served, as (PROCESS . LINE) conses.")

(defvar disasm-mcp--busy nil
  "Non-nil while a request is being served.
The filter is re-entered when a request waits for the debugger, so new
lines are only queued while this is set and are served afterwards.")

(defvar disasm-mcp--last-op nil
  "Name of the operation currently being served, for the mode line.")

(defvar disasm-mcp--log-entries nil
  "Log entries, oldest first.")

(defvar disasm-mcp--log-buffer nil
  "Buffer holding the agent log, or nil when it is not live.")

;;; JSON helpers

(defun disasm-mcp--json-ready (object)
  "Return OBJECT rewritten so that `json-serialize' can encode it.
Keyword plists become objects, lists and vectors become arrays, `nil'
becomes false, the `:json-null' marker becomes null and other symbols
become strings."
  (cond
   ((null object) :json-false)
   ((eq object t) t)
   ((eq object :json-null) :json-null)
   ((eq object :json-false) :json-false)
   ((vectorp object)
    (vconcat (mapcar #'disasm-mcp--json-ready object)))
   ((and (listp object) (keywordp (car object)))
    (let ((out nil)
          (rest object))
      (while rest
        (push (car rest) out)
        (push (disasm-mcp--json-ready (cadr rest)) out)
        (setq rest (cddr rest)))
      (nreverse out)))
   ((symbolp object) (symbol-name object))
   ((listp object)
    (vconcat (mapcar #'disasm-mcp--json-ready object)))
   (t object)))

(defun disasm-mcp--json (object)
  "Encode OBJECT as a JSON string, using null for Lisp nil."
  (json-serialize (disasm-mcp--json-ready object)
                  :null-object :json-null
                  :false-object :json-false))

(defun disasm-mcp--parse-json (string)
  "Parse the JSON object in STRING into an alist, or nil.
Objects use symbol keys and arrays become lists."
  (condition-case nil
      (json-parse-string string :object-type 'alist :array-type 'list)
    (error nil)))

;;; Arguments

(defun disasm-mcp--arg (args key &optional default)
  "Return KEY from the request argument alist ARGS, or DEFAULT."
  (let ((value (cdr (assq key args))))
    (cond ((or (null value) (eq value :null) (eq value :json-null)) default)
          (t value))))

(defun disasm-mcp--arg-string (args key &optional default)
  "Return KEY of ARGS as a string, or DEFAULT."
  (let ((value (disasm-mcp--arg args key)))
    (cond ((null value) default)
          ((stringp value) value)
          ((symbolp value) (symbol-name value))
          (t (format "%s" value)))))

(defun disasm-mcp--arg-number (args key &optional default)
  "Return KEY of ARGS as an integer, or DEFAULT.
Strings are read with `disasm-debug--parse-value', so they follow the
debugger convention (hexadecimal unless prefixed with \"0d\")."
  (let ((value (disasm-mcp--arg args key)))
    (cond ((null value) default)
          ((integerp value) value)
          ((floatp value) (truncate value))
          ((stringp value) (disasm-debug--parse-value value))
          (t (user-error "Invalid value for %s: %S" key value)))))

(defun disasm-mcp--arg-address (args key)
  "Return the address in KEY of ARGS as an integer."
  (let ((value (disasm-mcp--arg args key)))
    (cond ((null value) (user-error "No %s given" key))
          ((integerp value) value)
          ((stringp value)
           (unless (string-match-p "\\`[ \t]*\\(0[xX]\\)?[0-9a-fA-F]+[ \t]*\\'" value)
             (user-error "Invalid address: %s" value))
           (disasm--hex-to-int value))
          (t (user-error "Invalid address: %S" value)))))

(defun disasm-mcp--args-summary (args)
  "Return a short one-line rendering of the argument alist ARGS."
  (if (null args)
      ""
    (mapconcat (lambda (cell)
                 (format "%s=%s" (car cell)
                         (let ((value (cdr cell)))
                           (cond ((stringp value) value)
                                 ((or (null value) (eq value :null)) "-")
                                 (t (format "%S" value))))))
               args " ")))

;;; Sessions

(defun disasm-mcp--sessions ()
  "Return the live debug sessions, most recently used first."
  (let ((sessions nil))
    (dolist (buffer (buffer-list))
      (with-current-buffer buffer
        (when (bound-and-true-p disasm-debug--session)
          (cl-pushnew disasm-debug--session sessions))))
    (nreverse sessions)))

(defun disasm-mcp--session-id (session)
  "Return the identifier used to address SESSION."
  (let ((pid (disasm-debug-session-pid session)))
    (if pid
        (number-to-string pid)
      (or (disasm-debug-session-name session) "session"))))

(defun disasm-mcp--session-by-id (id)
  "Return the session identified by the string ID, or nil."
  (when id
    (cl-find (format "%s" id) (disasm-mcp--sessions)
             :key #'disasm-mcp--session-id :test #'equal)))

(defun disasm-mcp--session (args)
  "Return the session addressed by ARGS.
Without a \"session\" key the most recently used one is returned."
  (let ((id (disasm-mcp--arg-string args 'session))
        (sessions (disasm-mcp--sessions)))
    (cond
     ((null sessions) (user-error "No debugging session is running"))
     (id (or (disasm-mcp--session-by-id id)
             (user-error "No such session: %s" id)))
     (t (car sessions)))))

(defun disasm-mcp--bits (session)
  "Return the address size of SESSION in bits."
  (or (disasm-debug-session-bits session) 64))

(defun disasm-mcp--hex (session address)
  "Format ADDRESS the way SESSION displays addresses."
  (and address (disasm--format-address address (disasm-mcp--bits session))))

(defun disasm-mcp--session-json (session)
  "Return a JSON-ready description of SESSION."
  (list :id (disasm-mcp--session-id session)
        :name (or (disasm-debug-session-name session) "")
        :pid (or (disasm-debug-session-pid session) 0)
        :exe (or (disasm-debug-session-exe session) "")
        :state (disasm-debug-session-state-label session)
        :reason (or (disasm-debug-session-reason session) "")
        :bits (disasm-mcp--bits session)
        :arch (or (disasm-debug-session-arch session) "")
        :pc (or (disasm-debug-session-pc session) :json-null)
        :pc_hex (or (disasm-mcp--hex session
                                     (disasm-debug-session-pc session))
                    "")
        :main (disasm-mcp--main-path session)))

(defun disasm-mcp--main-path (session)
  "Return the path of SESSION's main executable."
  (or (disasm-debug-session-exe session) ""))

(defun disasm-mcp--state-json (session)
  "Return a JSON-ready snapshot of SESSION's execution state."
  (let ((hit (disasm-debug-session-hit-breakpoint session)))
    (list :id (disasm-mcp--session-id session)
          :name (or (disasm-debug-session-name session) "")
          :pid (or (disasm-debug-session-pid session) 0)
          :exe (disasm-mcp--main-path session)
          :state (disasm-debug-session-state-label session)
          :stopped (eq (disasm-debug-session-state session) 'stopped)
          :exited (eq (disasm-debug-session-state session) 'exited)
          :reason (or (disasm-debug-session-reason session) "")
          :hit_breakpoint (or hit :json-null)
          :pc (or (disasm-debug-session-pc session) :json-null)
          :pc_hex (or (disasm-mcp--hex session
                                       (disasm-debug-session-pc session))
                      "")
          :thread (or (disasm-debug-session-current-thread session) :json-null)
          :frame (or (disasm-debug-session-current-frame session) 0)
          :bits (disasm-mcp--bits session)
          :arch (or (disasm-debug-session-arch session) "")
          :breakpoints (length (disasm-debug-session-breakpoints session))
          :threads (length (disasm-debug-session-threads session)))))

;;; Memory reads waiting for the debugger

(defun disasm-mcp--wait-for-callback (session sender &optional timeout)
  "Call SENDER, a function taking a callback, and wait for it.
Return a cons of t and the argument list the callback was called with,
or nil when TIMEOUT (seconds, default 10) elapsed first.  SESSION's
debugger is pumped while waiting."
  (let* ((client (disasm-debug-session-client session))
         (process (and client (disasm-mi-client-process client)))
         (done nil)
         (value nil))
    (funcall sender (lambda (&rest args)
                      (setq value args)
                      (setq done t)))
    (let ((deadline (+ (float-time) (or timeout 10))))
      (while (and (not done)
                  (< (float-time) deadline)
                  (or (null process) (process-live-p process)))
        (accept-process-output process 0.02)))
    (and done (cons t value))))

;;; Operations

(defun disasm-mcp--op-ping (_args)
  "Answer a liveness probe."
  (list :pong t :time (float-time)))

(defun disasm-mcp--op-hello (_args)
  "Introduce the endpoint to a newly connected client."
  (list :version disasm-mcp-version
        :protocol disasm-mcp-protocol
        :emacs emacs-version
        :sessions (vconcat (mapcar #'disasm-mcp--session-json
                                   (disasm-mcp--sessions)))))

(defun disasm-mcp--op-sessions (_args)
  "List the debugging sessions currently open."
  (list :sessions (vconcat (mapcar #'disasm-mcp--session-json
                                   (disasm-mcp--sessions)))))

(defun disasm-mcp--session-section (session name)
  "Return the NAME section of SESSION as a JSON-ready plist."
  (pcase name
    ("registers" (disasm-mcp--registers-json session))
    ("flags" (list :flags (disasm-mcp--flags-json session)))
    ("threads" (list :threads (disasm-mcp--threads-json session)))
    ("frames" (list :frames (disasm-mcp--frames-json session)))
    ("modules" (list :modules (disasm-mcp--modules-json session)))
    ("breakpoints" (list :breakpoints (disasm-mcp--breakpoints-json session)))
    (_ (user-error "Unknown section: %s" name))))

(defun disasm-mcp--op-state (args)
  "Report the execution state of the session, with optional sections.
The \"include\" argument names extra sections: registers, flags,
threads, frames, modules and breakpoints."
  (let* ((session (disasm-mcp--session args))
         (include (disasm-mcp--arg args 'include))
         (result (disasm-mcp--state-json session)))
    (dolist (name (if (listp include) include (and include (list include))))
      ;; `plist-put' rather than `append': the sections we add may reuse a
      ;; key the snapshot already carries (the `:threads' and `:breakpoints'
      ;; counts), and the richer section has to win.
      (let ((section (disasm-mcp--session-section session name)))
        (while section
          (setq result (plist-put result (car section) (cadr section)))
          (setq section (cddr section)))))
    result))

(defun disasm-mcp--registers-json (session)
  "Return the registers of SESSION."
  (list :registers
        (vconcat
         (mapcar (lambda (cell)
                   (list :name (car cell)
                         :value (cdr cell)
                         :int (disasm--hex-to-int (cdr cell))))
                 (disasm-debug-session-registers session)))))

(defun disasm-mcp--flags-json (session)
  "Return the CPU flags of SESSION."
  (let ((flags (disasm-debug-session-flags session)))
    (list :eflags (or flags :json-null)
          :set (vconcat
                (delq nil
                      (mapcar (lambda (entry)
                                (and flags
                                     (disasm-debug-flag-set-p flags (nth 0 entry))
                                     (nth 0 entry)))
                              (disasm-debug-flags))))
          :all (vconcat (mapcar (lambda (entry)
                                  (list :name (nth 0 entry)
                                        :description (nth 2 entry)
                                        :set (and flags
                                                  (disasm-debug-flag-set-p
                                                   flags (nth 0 entry))
                                                  t)))
                                (disasm-debug-flags))))))

(defun disasm-mcp--threads-json (session)
  "Return the threads of SESSION."
  (let ((current (disasm-debug-session-current-thread session)))
    (vconcat
     (mapcar (lambda (thread)
               (list :id (disasm-debug-thread-id thread)
                     :name (or (disasm-debug-thread-name thread) "")
                     :target_id (or (disasm-debug-thread-target-id thread) "")
                     :state (or (disasm-debug-thread-state thread) "")
                     :current (and current
                                   (equal current (disasm-debug-thread-id thread))
                                   t)))
             (disasm-debug-session-threads session)))))

(defun disasm-mcp--frames-json (session)
  "Return the stack frames of SESSION."
  (let ((current (or (disasm-debug-session-current-frame session) 0))
        (delta (or (disasm-debug-session-delta session) 0)))
    (vconcat
     (mapcar (lambda (frame)
               (let ((addr (disasm-debug-frame-addr frame)))
                 (list :level (disasm-debug-frame-level frame)
                       :address (or addr :json-null)
                       :address_hex (or (and addr
                                             (disasm--format-address
                                              (+ addr delta) (disasm-mcp--bits session)))
                                        "")
                       :func (or (disasm-debug-frame-func frame) "")
                       :file (or (disasm-debug-frame-file frame) "")
                       :current (and (= (disasm-debug-frame-level frame) current)
                                     t))))
             (disasm-debug-session-frames session)))))

(defun disasm-mcp--modules-json (session)
  "Return the modules loaded in SESSION's target."
  (vconcat
   (mapcar (lambda (module)
             (list :path (or (disasm-debug-module-path module) "")
                   :from (or (disasm-debug-module-from module) 0)
                   :from_hex (or (disasm-mcp--hex session
                                                  (disasm-debug-module-from module))
                                 "")
                   :to (or (disasm-debug-module-to module) 0)
                   :to_hex (or (disasm-mcp--hex session
                                                (disasm-debug-module-to module))
                               "")
                   :main (and (disasm-debug-module-main-p module) t)))
           (disasm-debug-session-modules session))))

(defun disasm-mcp--breakpoint-json (session bp)
  "Return a JSON-ready description of the breakpoint BP of SESSION."
  (let ((hit (disasm-debug-session-hit-breakpoint session)))
    (list :number (disasm-debug-breakpoint-number bp)
          :address (or (disasm-debug-breakpoint-addr bp) :json-null)
          :address_hex (or (disasm-mcp--hex session
                                            (disasm-debug-breakpoint-addr bp))
                           "")
          :enabled (and (disasm-debug-breakpoint-enabled bp) t)
          :func (or (disasm-debug-breakpoint-func bp) "")
          :file (or (disasm-debug-breakpoint-file bp) "")
          :line (or (disasm-debug-breakpoint-line bp) :json-null)
          :hit (and hit (= hit (disasm-debug-breakpoint-number bp)) t))))

(defun disasm-mcp--breakpoints-json (session)
  "Return the breakpoints of SESSION."
  (vconcat (mapcar (lambda (bp) (disasm-mcp--breakpoint-json session bp))
                   (disasm-debug-session-breakpoints session))))

;;; Disassembly

(defun disasm-mcp--insn-marker (session address)
  "Return the marker character for ADDRESS in SESSION."
  (cond
   ((and (disasm-debug-session-pc session)
         (= address (disasm-debug-session-pc session)))
    "=>")
   ((disasm-debug--breakpoint-at session address) "*")
   (t "  ")))

(defun disasm-mcp--insn-json (session insn address)
  "Describe INSN of SESSION, which lives at live ADDRESS."
  (let* ((bits (disasm-mcp--bits session))
         (marker (disasm-mcp--insn-marker session address))
         (bytes (or (disasm-insn-bytes insn) ""))
         (mnemonic (or (disasm-insn-mnemonic insn) ""))
         (operands (or (disasm-insn-operands insn) ""))
         (hex (disasm--format-address address bits)))
    (list :address address
          :address_hex hex
          :bytes bytes
          :mnemonic mnemonic
          :operands operands
          :section (or (disasm-insn-section insn) "")
          :label (or (disasm-insn-label insn) "")
          :byte_count (length bytes)
          :marker (string-trim marker)
          :current (and (disasm-debug-session-pc session)
                        (= address (disasm-debug-session-pc session))
                        t)
          :text (format "%s %s  %-30s %-8s %s"
                        marker hex bytes mnemonic operands))))

(defun disasm-mcp--insns-result (session address source rows)
  "Assemble the result of a disassembly of SESSION at ADDRESS.
SOURCE says whether the instructions came from \"file\" or \"live\"
memory and ROWS are `disasm-mcp--insn-json' results."
  (list :session (disasm-mcp--session-id session)
        :address address
        :address_hex (disasm-mcp--hex session address)
        :source source
        :count (length rows)
        :instructions (vconcat rows)
        :text (mapconcat (lambda (row) (plist-get row :text)) rows "\n")))

(defun disasm-mcp--op-disassemble (args)
  "Disassemble a range of instructions around an address.
Instructions are read from the file that backs the address when
possible and from live memory otherwise; the target must be stopped
for the latter."
  (let* ((session (disasm-mcp--session args))
         (address (disasm-mcp--arg-address args 'address))
         (count (min (max (or (disasm-mcp--arg-number args 'count) 16) 1) 512))
         (delta (or (disasm-debug-session-delta session) 0))
         (listing (disasm-debug--listing-session session))
         (insns (and listing
                     (eq (disasm-session-state listing) 'ready)
                     (disasm-session-insns listing))))
    (if (and insns (> (length insns) 0)
             (let* ((file-addr (- address delta))
                    (idx (disasm-session-insn-index-for-addr listing file-addr)))
               (and idx (<= (- file-addr (disasm-insn-addr (aref insns idx))) 16))))
        (disasm-mcp--disassemble-file session listing address count delta)
      (disasm-mcp--disassemble-live session address count))))

(defun disasm-mcp--disassemble-file (session listing address count delta)
  "Disassemble COUNT instructions of SESSION's file listing at ADDRESS.
LISTING is the file session behind SESSION and DELTA maps its virtual
addresses to live ones."
  (let* ((insns (disasm-session-insns listing))
         (idx (disasm-session-insn-index-for-addr listing (- address delta)))
         (rows nil))
    (dotimes (i count)
      (let ((j (+ idx i)))
        (when (< j (length insns))
          (let ((insn (aref insns j)))
            (push (disasm-mcp--insn-json session insn
                                          (+ (disasm-insn-addr insn) delta))
                  rows)))))
    (disasm-mcp--insns-result session address "file" (nreverse rows))))

(defun disasm-mcp--disassemble-live (session address count)
  "Disassemble COUNT instructions of SESSION's live memory at ADDRESS."
  (unless (eq (disasm-debug-session-state session) 'stopped)
    (user-error "The target must be stopped to disassemble live memory"))
  (let* ((want (min disasm-debug-memory-window (max 64 (* count 16))))
         (bytes (disasm-debug--read-window session address want))
         (dsession (and bytes
                        (disasm-debug--live-session session bytes
                                                    (disasm-debug--arch session)
                                                    address))))
    (unless dsession
      (user-error "Cannot read and disassemble memory at %s"
                  (disasm-mcp--hex session address)))
    (let* ((insns (disasm-session-insns dsession))
           (idx (and (> (length insns) 0)
                     (disasm-session-insn-index-for-addr dsession address)))
           (rows nil))
      (dotimes (i count)
        (let ((j (and idx (+ idx i))))
          (when (and j (< j (length insns)))
            (let ((insn (aref insns j)))
              (push (disasm-mcp--insn-json session insn
                                            (disasm-insn-addr insn))
                    rows)))))
      (disasm-mcp--insns-result session address "live" (nreverse rows)))))

;;; Memory and registers

(defun disasm-mcp--ascii (bytes)
  "Render BYTES as a printable ASCII string."
  (mapconcat (lambda (byte)
               (if (and (>= byte 32) (< byte 127))
                   (char-to-string byte)
                 "."))
             (append bytes nil) ""))

(defun disasm-mcp--words (bytes size)
  "Read BYTES as little-endian words of SIZE bytes."
  (let ((words nil)
        (count (/ (length bytes) size))
        (i 0))
    (while (< i count)
      (push (disasm--unibyte-to-int bytes (* i size) size) words)
      (setq i (1+ i)))
    (nreverse words)))

(defun disasm-mcp--op-read-memory (args)
  "Read target memory.
The \"format\" argument selects how the bytes are reported: \"hex\"
default), \"ascii\", \"u8\", \"u16\", \"u32\", \"u64\" or \"int\"."
  (let* ((session (disasm-mcp--session args))
         (address (disasm-mcp--arg-address args 'address))
         (length (min (max (or (disasm-mcp--arg-number args 'length) 16) 1) 4096))
         (format (or (disasm-mcp--arg-string args 'format) "hex")))
    (unless (eq (disasm-debug-session-state session) 'stopped)
      (user-error "The target must be stopped to read memory"))
    (let ((bytes (disasm-debug-read-memory session address length)))
      (unless bytes
        (user-error "Cannot read %d bytes at %s" length
                    (disasm-mcp--hex session address)))
      (append
       (list :session (disasm-mcp--session-id session)
             :address address
             :address_hex (disasm-mcp--hex session address)
             :length (length bytes)
             :hex (disasm--unibyte-to-hex bytes)
             :ascii (disasm-mcp--ascii bytes)
             :u8 (vconcat bytes))
       (pcase format
         ("u8" (list :values (vconcat bytes)))
         ("u16" (list :values (vconcat (disasm-mcp--words bytes 2))))
         ("u32" (list :values (vconcat (disasm-mcp--words bytes 4))))
         ("u64" (list :values (vconcat (disasm-mcp--words bytes 8))))
         ("int" (list :value (disasm--unibyte-to-int bytes)))
         ("ascii" (list :value (disasm-mcp--ascii bytes)))
         (_ (list :text (disasm--unibyte-to-hex bytes))))
       (disasm-mcp--maybe-follow session address)))))

(defun disasm-mcp--maybe-follow (session address)
  "Move SESSION's listing to ADDRESS when the user asked to follow."
  (when (and disasm-mcp-follow-agent address)
    (ignore-errors (disasm-debug--goto-address session address)))
  nil)

(defun disasm-mcp--op-write-memory (args)
  "Write bytes into target memory.  The target must be stopped."
  (let* ((session (disasm-mcp--session args))
         (address (disasm-mcp--arg-address args 'address))
         (bytes (disasm-debug--parse-bytes (disasm-mcp--arg-string args 'bytes))))
    (unless (eq (disasm-debug-session-state session) 'stopped)
      (user-error "The target must be stopped to write memory"))
    (let ((result (disasm-mcp--wait-for-callback
                   session
                   (lambda (callback)
                     (disasm-debug--write-memory session address bytes callback)))))
      (unless (and result (car (cdr result)))
        (user-error "Cannot write memory at %s"
                    (disasm-mcp--hex session address)))
      (disasm-debug--after-memory-write session address)
      (list :session (disasm-mcp--session-id session)
            :address address
            :address_hex (disasm-mcp--hex session address)
            :written (length bytes)
            :hex (disasm--unibyte-to-hex bytes)))))

(defun disasm-mcp--op-set-register (args)
  "Set a register of the target.  The target must be stopped."
  (let* ((session (disasm-mcp--session args))
         (name (or (disasm-mcp--arg-string args 'name) ""))
         (value (disasm-mcp--arg-number args 'value)))
    (when (string-empty-p name)
      (user-error "No register name given"))
    (unless value
      (user-error "No value given for %s" name))
    (unless (eq (disasm-debug-session-state session) 'stopped)
      (user-error "The target must be stopped to edit registers"))
    (let ((result (disasm-mcp--wait-for-callback
                   session
                   (lambda (callback)
                     (disasm-debug--write-register session name value callback)))))
      (unless (and result (car (cdr result)))
        (user-error "Cannot set $%s" name))
      (disasm-debug--refresh-state session)
      (list :session (disasm-mcp--session-id session)
            :name name
            :value value
            :value_hex (format "0x%x" value)))))

;;; Navigation

(defun disasm-mcp--op-goto (args)
  "Show an address in the session's listing and hex pane."
  (let* ((session (disasm-mcp--session args))
         (address (disasm-mcp--arg-address args 'address)))
    (disasm-debug--goto-address session address)
    (list :session (disasm-mcp--session-id session)
          :address address
          :address_hex (disasm-mcp--hex session address))))

(defun disasm-mcp--op-select-thread (args)
  "Make a thread the current one.  The target must be stopped."
  (let* ((session (disasm-mcp--session args))
         (id (disasm-mcp--arg-string args 'id)))
    (unless id (user-error "No thread id given"))
    (disasm-debug-select-thread session id)
    (disasm-mcp--state-json session)))

(defun disasm-mcp--op-select-frame (args)
  "Select a stack frame.  The target must be stopped."
  (let* ((session (disasm-mcp--session args))
         (level (disasm-mcp--arg-number args 'level)))
    (unless level (user-error "No frame level given"))
    (disasm-debug-select-frame session level)
    (disasm-mcp--state-json session)))

;;; Breakpoints

(defun disasm-mcp--op-breakpoint (args)
  "Manage breakpoints.  The \"action\" is set, delete, clear or list."
  (let* ((session (disasm-mcp--session args))
         (action (or (disasm-mcp--arg-string args 'action) "list")))
    (pcase action
      ("list" (list :session (disasm-mcp--session-id session)
                    :breakpoints (disasm-mcp--breakpoints-json session)))
      ("set"
       (let ((address (disasm-mcp--arg-address args 'address)))
         (disasm-mcp--breakpoint-set session address)))
      ("delete"
       (let ((number (disasm-mcp--arg-number args 'number))
             (address-arg (disasm-mcp--arg args 'address)))
         (cond
          (number (disasm-mcp--breakpoint-delete session number))
          (address-arg
           (let* ((address (disasm-mcp--arg-address args 'address))
                  (bp (disasm-debug--breakpoint-at session address)))
             (unless bp
               (user-error "No breakpoint at %s"
                           (disasm-mcp--hex session address)))
             (disasm-mcp--breakpoint-delete
              session (disasm-debug-breakpoint-number bp))))
          (t (user-error "Give a breakpoint number or an address")))))
      ("clear" (disasm-mcp--breakpoint-clear session))
      (_ (user-error "Unknown breakpoint action: %s" action)))))

(defun disasm-mcp--breakpoint-set (session address)
  "Insert a breakpoint at the live ADDRESS of SESSION."
  (unless (eq (disasm-debug-session-state session) 'stopped)
    (user-error "The target must be stopped to change breakpoints"))
  (let ((existing (disasm-debug--breakpoint-at session address)))
    (if existing
        (list :session (disasm-mcp--session-id session)
              :address address
              :address_hex (disasm-mcp--hex session address)
              :number (disasm-debug-breakpoint-number existing)
              :existing t
              :breakpoints (disasm-mcp--breakpoints-json session))
      (let ((result (disasm-mcp--wait-for-callback
                     session
                     (lambda (callback)
                       (disasm-debug--break-insert session address callback)))))
        (let ((bp (and result (car (cdr result)))))
          (unless bp
            (user-error "Cannot set a breakpoint at %s"
                        (disasm-mcp--hex session address)))
          (setf (disasm-debug-session-breakpoints session)
                (append (disasm-debug-session-breakpoints session) (list bp)))
          (disasm-debug--after-breakpoint-change session)
          (list :session (disasm-mcp--session-id session)
                :address address
                :address_hex (disasm-mcp--hex session address)
                :number (disasm-debug-breakpoint-number bp)
                :breakpoints (disasm-mcp--breakpoints-json session)))))))

(defun disasm-mcp--breakpoint-delete (session number)
  "Delete the breakpoint NUMBER of SESSION."
  (unless (eq (disasm-debug-session-state session) 'stopped)
    (user-error "The target must be stopped to change breakpoints"))
  (let ((bp (cl-find number (disasm-debug-session-breakpoints session)
                     :key #'disasm-debug-breakpoint-number)))
    (unless bp
      (user-error "No such breakpoint: %d" number))
    (disasm-debug-delete-breakpoint session bp)
    ;; the deletion travels asynchronously; wait for the list to shrink
    (let ((deadline (+ (float-time) 2)))
      (while (and (memq bp (disasm-debug-session-breakpoints session))
                  (< (float-time) deadline))
        (accept-process-output nil 0.02)))
    (list :session (disasm-mcp--session-id session)
          :deleted number
          :breakpoints (disasm-mcp--breakpoints-json session))))

(defun disasm-mcp--breakpoint-clear (session)
  "Delete every breakpoint of SESSION."
  (unless (eq (disasm-debug-session-state session) 'stopped)
    (user-error "The target must be stopped to change breakpoints"))
  (let ((breakpoints (disasm-debug-session-breakpoints session)))
    (dolist (bp breakpoints)
      (disasm-debug--break-delete session (disasm-debug-breakpoint-number bp)))
    (setf (disasm-debug-session-breakpoints session) nil)
    (disasm-debug--after-breakpoint-change session)
    (list :session (disasm-mcp--session-id session)
          :cleared (length breakpoints)
          :breakpoints (disasm-mcp--breakpoints-json session))))

;;; Execution control

(defun disasm-mcp--op-step (args)
  "Step the target.  The \"mode\" is in, over or out."
  (let* ((session (disasm-mcp--session args))
         (mode (or (disasm-mcp--arg-string args 'mode) "in"))
         (operation (pcase mode
                      ("in" 'stepi)
                      ("over" 'nexti)
                      ("out" 'finish)
                      (_ (user-error "Unknown step mode: %s" mode)))))
    (unless (memq (disasm-debug-session-state session) '(stopped))
      (user-error "The target must be stopped to step"))
    (disasm-debug--exec session operation)
    (disasm-mcp--state-json session)))

(defun disasm-mcp--op-continue (args)
  "Resume the target."
  (let ((session (disasm-mcp--session args)))
    (unless (eq (disasm-debug-session-state session) 'stopped)
      (user-error "The target must be stopped to resume"))
    (disasm-debug--exec session 'continue)
    (disasm-mcp--state-json session)))

(defun disasm-mcp--op-interrupt (args)
  "Interrupt a running target."
  (let ((session (disasm-mcp--session args)))
    (if (eq (disasm-debug-session-state session) 'running)
        (progn
          (disasm-debug--exec session 'interrupt)
          (disasm-mcp--state-json session))
      (list :session (disasm-mcp--session-id session)
            :note "the target is not running"
            :state (disasm-debug-session-state-label session)))))

;;; Sessions

(defun disasm-mcp--op-attach (args)
  "Attach the debugger to a running process."
  (let* ((pid (disasm-mcp--arg-number args 'pid))
         (_ (unless pid (user-error "No process id given")))
         (name (or (disasm-mcp--arg-string args 'name)
                   (format "pid %d" pid))))
    (when (disasm-mcp--session-by-id (number-to-string pid))
      (user-error "Already attached to process %d" pid))
    (let ((session (disasm-attach (disasm-proc-entry--create :pid pid
                                                             :name name))))
      (disasm-mcp--session-json session))))

(defun disasm-mcp--op-launch (args)
  "Start a program under the debugger."
  (let* ((path (disasm-mcp--arg-string args 'path))
         (arguments (or (disasm-mcp--arg-string args 'arguments) "")))
    (unless (and path (not (string-empty-p path)))
      (user-error "No program path given"))
    (unless (file-regular-p path)
      (user-error "No such file: %s" path))
    (let ((session (disasm-debug-run (expand-file-name path) arguments)))
      (disasm-mcp--session-json session))))

(defun disasm-mcp--op-detach (args)
  "Detach the debugger from its target."
  (let ((session (disasm-mcp--session args)))
    (disasm-debug-detach session)
    (list :session (disasm-mcp--session-id session)
          :state (disasm-debug-session-state-label session))))

(defun disasm-mcp--op-open-file (args)
  "Open a static disassembly listing for a file.
This is a convenience for the user: it shows the file in the usual
listing so the agent and the human look at the same thing."
  (let ((path (disasm-mcp--arg-string args 'path)))
    (unless (and path (not (string-empty-p path)))
      (user-error "No file path given"))
    (disasm-file (expand-file-name path))
    (list :buffer (format "*disasm: %s*" (file-name-nondirectory path))
          :state "loading")))

;;; Dispatch

(defconst disasm-mcp--operations
  '(("ping" . disasm-mcp--op-ping)
    ("hello" . disasm-mcp--op-hello)
    ("sessions" . disasm-mcp--op-sessions)
    ("state" . disasm-mcp--op-state)
    ("disassemble" . disasm-mcp--op-disassemble)
    ("read_memory" . disasm-mcp--op-read-memory)
    ("write_memory" . disasm-mcp--op-write-memory)
    ("set_register" . disasm-mcp--op-set-register)
    ("goto" . disasm-mcp--op-goto)
    ("select_thread" . disasm-mcp--op-select-thread)
    ("select_frame" . disasm-mcp--op-select-frame)
    ("breakpoint" . disasm-mcp--op-breakpoint)
    ("step" . disasm-mcp--op-step)
    ("continue" . disasm-mcp--op-continue)
    ("interrupt" . disasm-mcp--op-interrupt)
    ("attach" . disasm-mcp--op-attach)
    ("launch" . disasm-mcp--op-launch)
    ("detach" . disasm-mcp--op-detach)
    ("open_file" . disasm-mcp--op-open-file))
  "Mapping of protocol operation names to handler functions.")

(defun disasm-mcp--dispatch (op args)
  "Run the operation OP with the argument alist ARGS.
Return the JSON-ready result plist, or signal an error."
  (let ((handler (cdr (assoc op disasm-mcp--operations))))
    (unless handler
      (user-error "Unknown operation: %s" op))
    (funcall handler args)))

;;; Agent log

(defun disasm-mcp--log-buffer ()
  "Return the buffer holding the agent log, creating it if needed."
  (unless (buffer-live-p disasm-mcp--log-buffer)
    (setq disasm-mcp--log-buffer (get-buffer-create "*disasm-agent*"))
    (with-current-buffer disasm-mcp--log-buffer
      (disasm-mcp-log-mode)))
  disasm-mcp--log-buffer)

(define-derived-mode disasm-mcp-log-mode special-mode "Disasm-Agent"
  "Major mode of the disasm agent log.
Every request served by the MCP endpoint is appended here, together
with the asynchronous events the debugger reports.  \\`RET' jumps to
the address of the entry at point; \\`TAB' shows or hides the detail
lines."
  (setq-local truncate-lines nil)
  ;; Start from an empty spec so that `disasm-mcp-log-toggle-details' can
  ;; really reveal the detail lines again (the default value of `t' would
  ;; keep every invisible run hidden).
  (setq-local buffer-invisibility-spec nil)
  (add-to-invisibility-spec 'disasm-mcp-log-detail)
  (setq-local header-line-format
              '(:eval (disasm-mcp--log-header))))

(defun disasm-mcp--log-header ()
  "Return the header line of the agent log."
  (format " MCP %s on %s:%s  |  %d connection%s  |  %s"
          (if (process-live-p disasm-mcp--server-process) "listening" "stopped")
          disasm-mcp-host (or disasm-mcp--port disasm-mcp-port)
          (length disasm-mcp--clients)
          (if (= 1 (length disasm-mcp--clients)) "" "s")
          (or disasm-mcp--last-op "idle")))

(defun disasm-mcp--log-line (entry)
  "Return the one-line rendering of ENTRY."
  (let ((op (plist-get entry :op))
        (ok (plist-get entry :ok))
        (summary (plist-get entry :summary)))
    (concat
     (propertize (format "%-12s " (or (plist-get entry :time) "")) 'face 'shadow)
     (if op
         (concat (propertize (format "%-16s" op) 'face 'disasm-mcp-log-op-face)
                 (propertize (format "%-30s" (or (plist-get entry :args) ""))
                             'face 'disasm-mcp-log-args-face))
       (concat (propertize (format "%-16s" "event") 'face 'disasm-mcp-log-event-face)
               (propertize (format "%-30s" (or (plist-get entry :kind) ""))
                           'face 'disasm-mcp-log-args-face)))
     (propertize (format "%s" (or summary (if ok "ok" "error")))
                 'face (if (eq ok :event)
                           'disasm-mcp-log-event-face
                         (if ok 'disasm-mcp-log-ok-face 'disasm-mcp-log-error-face))))))

(defun disasm-mcp--log-detail (entry)
  "Return the expandable detail line of ENTRY."
  (propertize
   (format "             %s" (plist-get entry :detail))
   'face 'disasm-mcp-log-detail-face
   'invisible 'disasm-mcp-log-detail))

(defun disasm-mcp--log-trim ()
  "Drop the oldest log rows so that at most `disasm-mcp-log-limit' remain."
  (when (> (length disasm-mcp--log-entries) disasm-mcp-log-limit)
    (let ((drop (- (length disasm-mcp--log-entries) disasm-mcp-log-limit)))
      (setq disasm-mcp--log-entries (nthcdr drop disasm-mcp--log-entries))
      (let ((cut nil)
            (seen 0))
        (save-excursion
          (goto-char (point-min))
          (while (and (not (eobp)) (null cut))
            (when (get-text-property (point) 'disasm-mcp-log-row)
              (setq seen (1+ seen))
              (when (= seen (1+ drop))
                (setq cut (line-beginning-position))))
            (forward-line 1)))
        (when cut
          (delete-region (point-min) cut))))))

(defun disasm-mcp--log (entry)
  "Append ENTRY to the agent log."
  (setq disasm-mcp--log-entries (append disasm-mcp--log-entries (list entry)))
  (let ((buffer (disasm-mcp--log-buffer)))
    (with-current-buffer buffer
      (let ((inhibit-read-only t)
            (follow (or (null (get-buffer-window buffer t))
                        (with-selected-window (get-buffer-window buffer t)
                          (= (point) (point-max))))))
        (save-excursion
          (goto-char (point-max))
          (insert (propertize (concat (disasm-mcp--log-line entry) "\n")
                              'disasm-mcp-log-row t
                              'disasm-mcp-entry entry
                              'disasm-mcp-address (plist-get entry :address)
                              'disasm-mcp-session (plist-get entry :session)))
          (insert (concat (disasm-mcp--log-detail entry) "\n"))
          (disasm-mcp--log-trim))
        (when (and follow (get-buffer-window buffer t))
          (with-selected-window (get-buffer-window buffer t)
            (goto-char (point-max))))))))

(defun disasm-mcp--log-call (op args result ok seconds session address)
  "Log one served request.
OP, ARGS, RESULT and OK describe it; SECONDS is the time it took and
SESSION/ADDRESS are the subject, when known."
  (disasm-mcp--log
   (list :time (format-time-string "%H:%M:%S" (current-time))
         :op op
         :args (disasm-mcp--args-summary args)
         :ok ok
         :session session
         :address address
         :summary (disasm-mcp--result-summary result ok seconds)
         :detail (format "%s %s" (disasm-mcp--args-summary args)
                         (condition-case nil
                             (truncate-string-to-width
                              (disasm-mcp--json result) 2000 nil nil "…")
                           (error ""))))))

(defun disasm-mcp--result-summary (result ok seconds)
  "Return a one-line summary of RESULT, OK and the elapsed SECONDS."
  (let ((time (format "(%.0f ms)" (* 1000 (or seconds 0)))))
    (if (null ok)
        (format "%s %s" (or (plist-get result :error) "error") time)
      (let ((parts nil))
        (dolist (key '(:state :reason :pc_hex :hit_breakpoint :count :written
                       :deleted :cleared :number :value_hex :buffer :breakpoints
                       :threads :frames))
          (let ((value (plist-get result key)))
            (when (and value (not (eq value :json-null))
                       (not (and (vectorp value) (zerop (length value)))))
              (push (format "%s=%s" (substring (symbol-name key) 1)
                            (if (vectorp value)
                                (length value)
                              value))
                    parts))))
        (format "%s %s" (if parts (mapconcat #'identity (nreverse parts) " ") "ok")
                time)))))

(defun disasm-mcp--log-event (session event)
  "Log the debugger EVENT of SESSION."
  (disasm-mcp--log
   (list :time (format-time-string "%H:%M:%S" (current-time))
         :ok :event
         :kind (symbol-name (or (plist-get event :kind) 'event))
         :session (disasm-mcp--session-id session)
         :summary (disasm-mcp--event-summary event)
         :detail (disasm-mcp--json event))))

(defun disasm-mcp--event-summary (event)
  "Return a one-line summary of the debugger EVENT."
  (let ((parts nil))
    (dolist (cell (list (cons "reason" (plist-get event :reason))
                        (cons "bkpt" (plist-get event :breakpoint))
                        (cons "thread" (plist-get event :thread))
                        (cons "status" (plist-get event :status))))
      (when (cdr cell)
        (push (format "%s=%s" (car cell) (cdr cell)) parts)))
    (mapconcat #'identity (nreverse parts) " ")))

(defun disasm-mcp--on-event (session event)
  "Record the debugger EVENT of SESSION in the agent log."
  (disasm-mcp--log-event session event))

(add-hook 'disasm-debug-event-hook #'disasm-mcp--on-event)

;;; Log commands

(defun disasm-mcp-log-entry-at-point ()
  "Return the log entry at point, or nil."
  (get-text-property (point) 'disasm-mcp-entry))

(defun disasm-mcp-log-goto ()
  "Jump to the address of the log entry at point."
  (interactive)
  (let* ((entry (disasm-mcp-log-entry-at-point))
         (address (plist-get entry :address)))
    (unless entry
      (user-error "No entry on this line"))
    (unless (and address (integerp address))
      (user-error "This entry has no address"))
    (let ((session (disasm-mcp--session-by-id (plist-get entry :session))))
      (if session
          (disasm-debug--goto-address session address)
        (user-error "That session is no longer open")))))

(defun disasm-mcp-log-toggle-details ()
  "Show or hide the detail lines of the agent log."
  (interactive)
  (if (memq 'disasm-mcp-log-detail buffer-invisibility-spec)
      (remove-from-invisibility-spec 'disasm-mcp-log-detail)
    (add-to-invisibility-spec 'disasm-mcp-log-detail)))

(defun disasm-mcp-log-clear ()
  "Erase the agent log."
  (interactive)
  (let ((buffer (disasm-mcp--log-buffer)))
    (with-current-buffer buffer
      (let ((inhibit-read-only t))
        (erase-buffer)))
    (setq disasm-mcp--log-entries nil)))

(define-key disasm-mcp-log-mode-map (kbd "RET") #'disasm-mcp-log-goto)
(define-key disasm-mcp-log-mode-map (kbd "TAB") #'disasm-mcp-log-toggle-details)
(define-key disasm-mcp-log-mode-map (kbd "<backtab>")
  #'disasm-mcp-log-toggle-details)
(define-key disasm-mcp-log-mode-map (kbd "c") #'disasm-mcp-log-clear)

;;;###autoload
(defun disasm-mcp-log ()
  "Show the log of the agent's activity."
  (interactive)
  (pop-to-buffer (disasm-mcp--log-buffer)))

;;; The listener

(defun disasm-mcp--token-path ()
  "Return the file the access token is written to."
  (expand-file-name (or disasm-mcp-token-file
                        (locate-user-emacs-file "disasm-mcp-token"))))

(defun disasm-mcp--new-token ()
  "Return a fresh random access token."
  (format "%08x%08x%08x"
          (random most-positive-fixnum)
          (random most-positive-fixnum)
          (random most-positive-fixnum)))

(defun disasm-mcp--write-token ()
  "Write the current token to `disasm-mcp--token-path'."
  (let ((path (disasm-mcp--token-path)))
    (with-temp-file path
      (insert disasm-mcp--token "\n"))
    (ignore-errors (set-file-modes path #o600))))

(defun disasm-mcp--delete-token ()
  "Remove the token file, if it exists."
  (ignore-errors (delete-file (disasm-mcp--token-path))))

;;;###autoload
(defun disasm-mcp-start ()
  "Start the MCP listener."
  (interactive)
  (when (process-live-p disasm-mcp--server-process)
    (user-error "The MCP listener is already running on port %s"
                disasm-mcp--port))
  (setq disasm-mcp--token (disasm-mcp--new-token))
  (disasm-mcp--write-token)
  (condition-case err
      (setq disasm-mcp--server-process
            (make-network-process
             :name "disasm-mcp"
             :server t
             :host disasm-mcp-host
             :service disasm-mcp-port
             :family 'ipv4
             :coding 'utf-8-unix
             :noquery t
             :filter #'disasm-mcp--filter
             :sentinel #'disasm-mcp--sentinel
             :log #'disasm-mcp--log-connection))
    (error
     (setq disasm-mcp--server-process nil)
     (user-error "Cannot start the MCP listener on %s:%s: %s"
                 disasm-mcp-host disasm-mcp-port (error-message-string err))))
  ;; With `:service t' the system picks the port, so record what we got.
  (setq disasm-mcp--port (or (process-contact disasm-mcp--server-process :service)
                             disasm-mcp-port))
  (setq disasm-mcp--clients nil)
  (message "disasm-mcp: listening on %s:%s (token in %s)"
           disasm-mcp-host disasm-mcp--port (disasm-mcp--token-path)))

;;;###autoload
(defun disasm-mcp-stop ()
  "Stop the MCP listener."
  (interactive)
  (when (process-live-p disasm-mcp--server-process)
    (delete-process disasm-mcp--server-process))
  (setq disasm-mcp--server-process nil)
  (setq disasm-mcp--port nil)
  (setq disasm-mcp--clients nil)
  (disasm-mcp--delete-token)
  (message "disasm-mcp: stopped"))

(defun disasm-mcp--running-p ()
  "Return non-nil when the MCP listener is up."
  (process-live-p disasm-mcp--server-process))

(defun disasm-mcp--log-connection (server connection message)
  "Note the connection event MESSAGE on SERVER.
CONNECTION is the new connection process, except for messages about
the listening socket itself."
  (ignore server)
  (when (and (processp connection) (string-prefix-p "accept" message))
    (message "disasm-mcp: connection from %s"
             (or (process-contact connection :host) "?"))))

(defun disasm-mcp--sentinel (process _message)
  "Drop PROCESS from the client list once it dies."
  (unless (process-live-p process)
    (setq disasm-mcp--clients (delq process disasm-mcp--clients))))

(defun disasm-mcp--filter (process chunk)
  "Collect CHUNK from PROCESS and serve every complete line in it."
  (let* ((text (concat (or (process-get process 'disasm-mcp-acc) "") chunk))
         (lines (split-string text "\n"))
         (rest (car (last lines))))
    (process-put process 'disasm-mcp-acc rest)
    (unless (memq process disasm-mcp--clients)
      (push process disasm-mcp--clients))
    (dolist (line (butlast lines))
      (let ((line (string-trim-right line "\r")))
        (unless (string-empty-p line)
          (setq disasm-mcp--queue
                (append disasm-mcp--queue (list (cons process line)))))))
    (disasm-mcp--drain)))

(defun disasm-mcp--drain ()
  "Serve the queued requests, one at a time."
  (unless disasm-mcp--busy
    (let ((disasm-mcp--busy t))
      (unwind-protect
          (while disasm-mcp--queue
            (let ((item (pop disasm-mcp--queue)))
              (condition-case err
                  (disasm-mcp--serve (car item) (cdr item))
                (error
                 (message "disasm-mcp: %s" (error-message-string err))))))
        (setq disasm-mcp--busy nil)
        (setq disasm-mcp--last-op nil)))))

(defun disasm-mcp--serve (process line)
  "Serve the request LINE received on PROCESS."
  (let* ((request (disasm-mcp--parse-json line))
         (id (and request (alist-get 'id request)))
         (token (and request (disasm-mcp--arg-string request 'token)))
         (op (and request (disasm-mcp--arg-string request 'op)))
         (args (let ((value (and request (alist-get 'args request))))
                 (and (listp value) value)))
         (start (float-time)))
    (cond
     ((null request)
      (disasm-mcp--respond process id nil
                           (list :error "Malformed JSON request"
                                 :kind "protocol")))
     ((not (and op (equal token disasm-mcp--token)))
      (disasm-mcp--respond process id nil
                           (list :error "Missing or invalid token"
                                 :kind "auth"))
      (disasm-mcp--count-failure process))
     (t
      (setq disasm-mcp--last-op op)
      (let* ((outcome (condition-case err
                          (cons t (disasm-mcp--dispatch op args))
                        (user-error (cons nil (list :error (error-message-string err)
                                                    :kind "user-error")))
                        (error (cons nil (list :error (error-message-string err)
                                               :kind "error")))))
             (ok (car outcome))
             (payload (cdr outcome)))
        (if ok
            (disasm-mcp--respond process id payload nil)
          (disasm-mcp--respond process id nil payload))
        (unless (equal op "ping")
          (disasm-mcp--log-call op args (if ok payload (list :error (plist-get payload :error)))
                                (and ok t)
                                (- (float-time) start)
                                (or (and ok (plist-get payload :session))
                                    (disasm-mcp--arg args 'session))
                                (and ok (disasm-mcp--focus-address payload)))))))))

(defun disasm-mcp--count-failure (process)
  "Count a rejected request on PROCESS, dropping it after a few."
  (let ((count (1+ (or (process-get process 'disasm-mcp-failures) 0))))
    (process-put process 'disasm-mcp-failures count)
    (when (> count 5)
      (message "disasm-mcp: too many bad requests; dropping the connection")
      (delete-process process))))

(defun disasm-mcp--focus-address (payload)
  "Return the address a result PAYLOAD is about, or nil."
  (let ((value (or (plist-get payload :address) (plist-get payload :pc))))
    (and (integerp value) value)))

(defun disasm-mcp--respond (process id payload error)
  "Send a response to PROCESS.
ID is echoed back, PAYLOAD carries a successful result and ERROR the
plist describing a failure."
  (let ((response (if error
                      (list :id (or id :json-null)
                            :ok :json-false
                            :error (or (plist-get error :error) "failed")
                            :kind (or (plist-get error :kind) "error"))
                    (list :id (or id :json-null)
                          :ok t
                          :result (or payload (list :done t))))))
    (when (process-live-p process)
      (condition-case err
          (process-send-string process (concat (disasm-mcp--json response) "\n"))
        (error (message "disasm-mcp: cannot answer: %s"
                        (error-message-string err)))))))

;;; Mode line indicator

(defun disasm-mcp--lighter ()
  "Return the mode line lighter of the MCP endpoint."
  (cond
   ((not (disasm-mcp--running-p)) " mcp:off")
   (disasm-mcp--busy (format " mcp:%s" (or disasm-mcp--last-op "work")))
   (disasm-mcp--clients (format " mcp:%d" (length disasm-mcp--clients)))
   (t " mcp")))

(define-minor-mode disasm-mcp-mode
  "Global minor mode showing the MCP endpoint in the mode line.
It does not start or stop the listener; see `disasm-mcp-start'."
  :global t
  :group 'disasm-mcp
  :lighter (:eval (disasm-mcp--lighter)))

(provide 'disasm-mcp)

;; Starting a listener from a batch process would be pointless and would
;; make the test suite depend on a free port, so only interactive Emacs
;; (including a daemon) starts one by itself.
(when (and disasm-mcp-auto-start (or (not noninteractive) (daemonp)))
  (condition-case err
      (disasm-mcp-start)
    (error (message "disasm-mcp: %s" (error-message-string err)))))
(disasm-mcp-mode 1)

;;; disasm-mcp.el ends here
