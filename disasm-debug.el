;;; disasm-debug.el --- Live debugging UI for disasm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://github.com/dmitryemacs/disasm

;;; Commentary:

;; The user interface of the `disasm' debugger: attaching to a running
;; process, the x64dbg-like debug layout and the glue that keeps the
;; listing, the hex pane and the registers/flags/stack panes in step with
;; the debugged process.  The backend-neutral session state comes from
;; `disasm-debug-core'; the actual debugger is driven through
;; `disasm-debug-gdb'.
;;
;;   M-x disasm-attach    attach to a running process (C-c d a)
;;
;; Once attached the right-hand column shows the registers, the flags and
;; the call stack; the listing follows the program counter and the
;; instruction at the PC is highlighted.

;;; Code:

(require 'cl-lib)
(require 'subr-x)
(require 'disasm-core)
(require 'disasm-backend)
(require 'disasm-debug-core)
(require 'disasm-debug-gdb)
(require 'disasm-registers)
(require 'disasm-mode)
(require 'disasm-hex)
(require 'disasm-proc)

(declare-function disasm--build-session "disasm" (file &optional raw))
(declare-function disasm--split-fraction "disasm" (window fraction side))
(declare-function disasm--apply-result "disasm-mode" (session parsed))
(declare-function disasm--insn-at-point "disasm-mode" ())
(declare-function disasm-sync--tick "disasm-hex" ())
(declare-function disasm-goto-address "disasm-mode" (addr))
(declare-function disasm-hex--get-buffer "disasm-hex" (session))
(declare-function disasm-hex--render-live "disasm-hex" (base bytes bits))
(declare-function disasm-debug-pane--address-at-point "disasm-registers" ())

;;; State

(defvar-local disasm-debug--session nil
  "The `disasm-debug-session' driving this listing buffer.")

(defvar-local disasm-debug--pc-overlay nil
  "Overlay marking the program counter in this listing buffer.")

(defvar-local disasm-debug--laid-out nil
  "Non-nil once the debug layout has been built for this buffer.")

(defun disasm-debug--current-session ()
  "Return the debug session of the current buffer, or signal an error."
  (or (disasm-debug--maybe-session)
      (user-error "No debugging session in this buffer")))

(defun disasm-debug--maybe-session ()
  "Return the debug session of the current buffer, or nil."
  (cond
   ((bound-and-true-p disasm-debug--session) disasm-debug--session)
   ((bound-and-true-p disasm-debug-pane-session) disasm-debug-pane-session)
   (t nil)))

(defun disasm-debug--listing-session (session)
  "Return the `disasm-session' shown in SESSION's listing buffer."
  (let ((listing (disasm-debug-session-listing session)))
    (and (buffer-live-p listing)
         (buffer-local-value 'disasm--session listing))))

;;; Address mapping

(defun disasm-debug--first-vma (dsession)
  "Return the lowest virtual address of the loaded sections of DSESSION."
  (let ((min nil))
    (dolist (section (disasm-session-sections dsession))
      (when (and (> (disasm-section-size section) 0)
                 (or (null min) (< (disasm-section-vma section) min)))
        (setq min (disasm-section-vma section))))
    (or min 0)))

(defun disasm-debug--live-to-file (session addr)
  "Translate live address ADDR to a file virtual address for SESSION."
  (- addr (or (disasm-debug-session-delta session) 0)))

;;; Live memory

(defun disasm-debug-read-memory (session address length)
  "Read LENGTH bytes of SESSION's target memory at live ADDRESS.
Return a unibyte string, or nil when the memory is unavailable or the
target is not stopped.  This dispatches to the debugger backend."
  (when (and (eq (disasm-debug-session-state session) 'stopped)
             (> length 0))
    (pcase (disasm-debug-session-backend session)
      ('gdb-mi (disasm-debug-gdb-read-memory session address length))
      (_ nil))))

(defun disasm-debug--read-window (session address length)
  "Read up to LENGTH bytes at ADDRESS in SESSION's target.
Return a unibyte string, or nil when even a small read fails.  The
requested size is halved whenever the range crosses unmapped memory."
  (let ((len length)
        (result nil))
    (while (and (not result) (>= len 16))
      (setq result (disasm-debug-read-memory session address len))
      (unless result (setq len (/ len 2))))
    result))

(defun disasm-debug--read-pointer (session address)
  "Read a pointer-sized value at ADDRESS in SESSION's target."
  (let* ((bits (or (disasm-debug-session-bits session) 64))
         (bytes (disasm-debug-read-memory session address (/ bits 8))))
    (when bytes (disasm--unibyte-to-int bytes))))

(defun disasm-debug--live-file (session)
  "Return the temporary file used to disassemble live memory for SESSION."
  (or (disasm-debug-session-live-file session)
      (let ((file (make-temp-file "disasm-live-" nil ".bin")))
        (setf (disasm-debug-session-live-file session) file)
        file)))

(defun disasm-debug--arch (session)
  "Return the architecture string to use for live disassembly in SESSION."
  (let* ((listing (disasm-debug--listing-session session))
         (arch (and listing (disasm-session-arch listing))))
    (if (and arch (not (string-empty-p arch))) arch disasm-raw-arch)))

(defun disasm-debug--live-session (session bytes arch base)
  "Disassemble BYTES as raw code for SESSION at live address BASE.
ARCH is the target architecture.  Return a ready `disasm-session', or
nil when the disassembly fails."
  (let ((file (disasm-debug--live-file session)))
    (let ((coding-system-for-write 'binary))
      (write-region bytes nil file nil 'silent))
    (condition-case err
        (let* ((raw (list :arch arch :base base))
               (dsession (disasm--build-session file raw)))
          (disasm--apply-result
           dsession
           (disasm-backend-disassemble file
                                       (disasm-session-sections dsession)
                                       (disasm-session-all-sections dsession)
                                       raw))
          dsession)
      (error
       (message "disasm: live disassembly failed: %s" (error-message-string err))
       nil))))

(defun disasm-debug--display-live (session address)
  "Disassemble live memory at ADDRESS and show it in SESSION's listing."
  (let ((bytes (disasm-debug--read-window session address
                                          disasm-debug-memory-window)))
    (if (null bytes)
        (message "disasm: cannot read memory at %s"
                 (disasm--format-address
                  address (or (disasm-debug-session-bits session) 64)))
      (let ((dsession (disasm-debug--live-session
                       session bytes (disasm-debug--arch session) address)))
        (when dsession
          (let ((listing (disasm-debug-session-listing session)))
            (setf (disasm-debug-session-file session) nil)
            (setf (disasm-debug-session-delta session) 0)
            (with-current-buffer listing
              (setq-local disasm--session dsession)
              (setq-local disasm-debug--session session)
              (setq-local disasm--live-label
                          (format "live %s"
                                  (disasm--format-address
                                   address (or (disasm-debug-session-bits session) 64))))
              (setf (disasm-session-buffer dsession) listing)
              (disasm-render)
              (ignore-errors (disasm-goto-address address))
              (disasm-debug--highlight-pc session address))
            (disasm-debug--set-drivers session)
            (disasm-debug--refresh-live-hex session)))))))

;;; Highlighting

(defun disasm-debug--refresh-pc-overlay ()
  "Re-apply the program-counter overlay in the current listing buffer.
Called after (re)rendering when the current buffer is a debug listing.
Also refreshes the live hex pane, which follows the listing."
  (when (and (bound-and-true-p disasm-debug--session)
             (disasm-debug-session-pc disasm-debug--session))
    (disasm-debug--highlight-pc
     disasm-debug--session
     (disasm-debug--live-to-file disasm-debug--session
                                 (disasm-debug-session-pc disasm-debug--session)))
    (disasm-debug--refresh-live-hex disasm-debug--session)))

(defun disasm-debug--highlight-pc (session addr)
  "Highlight the instruction covering file address ADDR in SESSION's listing."
  (let ((listing (disasm-debug-session-listing session)))
    (when (buffer-live-p listing)
      (with-current-buffer listing
        (when (overlayp disasm-debug--pc-overlay)
          (delete-overlay disasm-debug--pc-overlay))
        (setq disasm-debug--pc-overlay nil)
        (let* ((dsession disasm--session)
               (insns (and dsession (disasm-session-insns dsession)))
               (idx (and insns (> (length insns) 0)
                         (disasm-session-insn-index-for-addr dsession addr))))
          (when (and idx (< idx (length insns)))
            (goto-char (point-min))
            (forward-line (1- (disasm-insn-line (aref insns idx))))
            (setq disasm-debug--pc-overlay
                  (make-overlay (line-beginning-position) (line-end-position)))
            (overlay-put disasm-debug--pc-overlay 'face 'disasm-debug-pc-face)
            (overlay-put disasm-debug--pc-overlay 'priority 10)))))))

;;; Showing an address in the listing

(defun disasm-debug--goto-live (session addr)
  "Move SESSION's listing to the live address ADDR."
  (let* ((listing (disasm-debug-session-listing session))
         (file-addr (disasm-debug--live-to-file session addr))
         (dsession (disasm-debug--listing-session session)))
    (with-current-buffer listing
      (when (eq (disasm-session-state dsession) 'ready)
        (condition-case nil
            (disasm-goto-address file-addr)
          (error nil)))
      (disasm-debug--highlight-pc session file-addr))))

(defun disasm-debug--display-module (session module addr)
  "Show MODULE in SESSION's listing and move to the live address ADDR."
  (let ((file (disasm-debug-module-path module)))
    (if (equal file (disasm-debug-session-file session))
        (disasm-debug--goto-live session addr)
      (let* ((listing (disasm-debug-session-listing session))
             (dsession (disasm--build-session file))
             (delta (- (disasm-debug-module-from module)
                       (disasm-debug--first-vma dsession))))
        (setf (disasm-debug-session-file session) file)
        (setf (disasm-debug-session-delta session) delta)
        (with-current-buffer listing
          (setq-local disasm--session dsession)
          (setq-local disasm-debug--session session)
          (setq-local disasm--live-label nil)
          (setf (disasm-session-buffer dsession) listing)
          (disasm-render)
          (disasm--begin-disassembly dsession listing
                                     (disasm-debug--live-to-file session addr)))
        (disasm-debug--set-drivers session)
        (disasm-debug--highlight-pc session (disasm-debug--live-to-file session addr))))))

(defun disasm-debug--show-pc (session)
  "Show the program counter of SESSION in its listing buffer."
  (let ((pc (disasm-debug-session-pc session)))
    (when pc
      (let ((module (disasm-debug-module-for-address
                     (disasm-debug-session-modules session) pc)))
        (if (and module
                 (disasm-debug-module-path module)
                 (file-regular-p (disasm-debug-module-path module)))
            (disasm-debug--display-module session module pc)
          (disasm-debug--display-live session pc))))))

;;; Layout

(defun disasm-debug--listing-name (session)
  "Return the listing buffer name for SESSION."
  (format "*disasm-debug: %s (%d)*"
          (or (disasm-debug-session-name session) "process")
          (or (disasm-debug-session-pid session) 0)))

(defun disasm-debug--placeholder-session (session)
  "Return a placeholder `disasm-session' for SESSION before it is attached."
  (disasm-session--create
   :file (or (disasm-debug-session-name session) "")
   :format "" :arch "" :bits 64 :backend disasm-backend
   :insns [] :state 'loading))

(defun disasm-debug--ensure-layout (session)
  "Build the debug layout for SESSION the first time it is refreshed."
  (let ((listing (disasm-debug-session-listing session)))
    (unless (buffer-local-value 'disasm-debug--laid-out listing)
      (let ((registers (disasm-debug-pane--get-buffer session 'registers))
            (flags (disasm-debug-pane--get-buffer session 'flags))
            (stack (disasm-debug-pane--get-buffer session 'stack))
            (hexbuf (disasm-debug--live-hex-buffer session)))
        (pop-to-buffer listing)
        (let* ((win (or (get-buffer-window listing) (selected-window)))
               (right (disasm--split-fraction win
                                              (/ disasm-debug-sidebar-width 100.0)
                                              'right))
               (regwin (disasm--split-fraction right
                                               (/ disasm-registers-split 100.0)
                                               'above))
               (flagwin (disasm--split-fraction right
                                                (/ disasm-flags-split 100.0)
                                                'above)))
          (set-window-buffer regwin registers)
          (set-window-buffer flagwin flags)
          (set-window-buffer right stack)
          ;; Left column: the live hex pane below the listing.
          (let ((hexwin (disasm--split-fraction win
                                                (/ disasm-hex-height 100.0)
                                                'below)))
            (set-window-buffer hexwin hexbuf))
          (select-window win)))
      (with-current-buffer listing
        (setq-local disasm-debug--laid-out t))
      (disasm-debug--set-drivers session)
      (when (fboundp 'disasm-sync-mode)
        (disasm-sync-mode 1)
        (disasm-sync--tick)))))

;;; Live hex pane

(defun disasm-debug--live-hex-buffer (session)
  "Create (or return) the live hex pane buffer for SESSION."
  (let ((buffer (or (and (buffer-live-p (disasm-debug-session-hex-buffer session))
                         (disasm-debug-session-hex-buffer session))
                    (get-buffer-create
                     (format "*disasm-hex: %s (%d)*"
                             (or (disasm-debug-session-name session) "process")
                             (or (disasm-debug-session-pid session) 0))))))
    (with-current-buffer buffer
      (disasm-hex-mode)
      (setq-local disasm-hex--live t)
      (setq-local disasm-hex--bits (or (disasm-debug-session-bits session) 64))
      (setq-local disasm-debug--session session)
      (setq-local disasm--session (disasm-debug--listing-session session)))
    (setf (disasm-debug-session-hex-buffer session) buffer)
    (setf (disasm-debug-session-hex-base session) nil)
    (setf (disasm-debug-session-hex-length session) 0)
    buffer))

(defun disasm-debug--set-drivers (session)
  "Install the live synchronization drivers on SESSION's pane buffers."
  (let ((listing (disasm-debug-session-listing session))
        (hexbuf (disasm-debug-session-hex-buffer session)))
    (when (buffer-live-p listing)
      (with-current-buffer listing
        (setq-local disasm--sync-driver
                    (lambda (window) (disasm-debug--listing-drives session window)))))
    (when (buffer-live-p hexbuf)
      (with-current-buffer hexbuf
        (setq-local disasm--sync-driver
                    (lambda (window) (disasm-debug--hex-drives session window)))
        (setq-local disasm-hex--goto-live
                    (lambda (address)
                      (disasm-debug--goto-address session address)))))))

(defun disasm-debug--listing-live-address (session)
  "Return the live address of the instruction at point in SESSION's listing."
  (let ((listing (disasm-debug-session-listing session)))
    (when (buffer-live-p listing)
      (with-current-buffer listing
        (let ((insn (and disasm--session (disasm--insn-at-point))))
          (when insn
            (+ (disasm-insn-addr insn)
               (or (disasm-debug-session-delta session) 0))))))))

(defun disasm-debug--load-live-hex (session address)
  "Read a window of live memory around ADDRESS into SESSION's hex pane."
  (let* ((window disasm-debug-hex-window)
         (bits (or (disasm-debug-session-bits session) 64))
         (aligned (disasm--align-down address 16))
         (base (max 0 (- aligned 64)))
         (bytes (disasm-debug-read-memory session base window)))
    (unless bytes
      (setq base aligned)
      (setq bytes (disasm-debug--read-window session base window)))
    (let ((hexbuf (disasm-debug-session-hex-buffer session)))
      (when (buffer-live-p hexbuf)
        (if bytes
            (progn
              (setf (disasm-debug-session-hex-base session) base)
              (setf (disasm-debug-session-hex-length session) (length bytes))
              (with-current-buffer hexbuf
                (disasm-hex--render-live base bytes bits)
                (setq-local disasm--session (disasm-debug--listing-session session))))
          (setf (disasm-debug-session-hex-base session) nil)
          (setf (disasm-debug-session-hex-length session) 0)
          (with-current-buffer hexbuf
            (let ((inhibit-read-only t))
              (erase-buffer)
              (insert (propertize ";; live memory unavailable\n"
                                  'face 'disasm-comment-face)))))))))

(defun disasm-debug--show-live-address (session address size)
  "Ensure SESSION's hex pane covers ADDRESS, then highlight SIZE bytes."
  (let* ((base (disasm-debug-session-hex-base session))
         (len (disasm-debug-session-hex-length session)))
    (unless (and base len (> len 0) (<= base address) (< address (+ base len)))
      (disasm-debug--load-live-hex session address)
      (setq base (disasm-debug-session-hex-base session)
            len (disasm-debug-session-hex-length session)))
    (when (and base len (> len 0) (<= base address) (< address (+ base len)))
      (let* ((index (- address base))
             (hexbuf (disasm-debug-session-hex-buffer session)))
        (when (buffer-live-p hexbuf)
          (with-current-buffer hexbuf
            (disasm--sync-window (get-buffer-window hexbuf) hexbuf
                                 (1+ (/ index 16))))
          (disasm--hex-highlight-bytes hexbuf index size))))))

(defun disasm-debug--refresh-live-hex (session)
  "Refresh SESSION's live hex pane around the listing's current address."
  (when (buffer-live-p (disasm-debug-session-hex-buffer session))
    (let ((address (disasm-debug--listing-live-address session)))
      (when address
        (disasm-debug--show-live-address session address nil)))))

(defun disasm-debug--listing-drives (session _window)
  "Sync SESSION's live hex pane from its listing."
  (disasm-debug--refresh-live-hex session))

(defun disasm-debug--hex-drives (session window)
  "Sync SESSION's listing from its live hex pane WINDOW."
  (when (disasm-debug-session-hex-base session)
    (let* ((hexbuf (window-buffer window))
           (line (line-number-at-pos (window-point window)))
           (index (* 16 (1- line)))
           (live-addr (+ (disasm-debug-session-hex-base session) index))
           (delta (or (disasm-debug-session-delta session) 0))
           (file-addr (- live-addr delta))
           (listing (disasm-debug-session-listing session)))
      (when (buffer-live-p listing)
        (with-current-buffer listing
          (when (and disasm--session
                     (eq (disasm-session-state disasm--session) 'ready)
                     (> (length (disasm-session-insns disasm--session)) 0))
            (let* ((insns (disasm-session-insns disasm--session))
                   (idx (disasm-session-insn-index-for-addr disasm--session file-addr)))
              (when idx
                (disasm--sync-window (get-buffer-window listing) listing
                                     (disasm-insn-line (aref insns idx))))))))
      (with-current-buffer hexbuf
        (disasm--hex-highlight-bytes hexbuf index 16)))))

;;; Refresh

(defun disasm-debug--ui-refresh (session)
  "Update SESSION's panes, listing and layout from its state."
  (condition-case err
      (progn
        (disasm-debug--ensure-layout session)
        (disasm-debug--show-pc session)
        (disasm-debug--refresh-live-hex session)
        (disasm-debug-pane--refresh session))
    (error (message "disasm: %s" (error-message-string err)))))

(defun disasm-debug--on-exit (session status)
  "Handle the debugger of SESSION exiting with STATUS."
  (unless (memq (disasm-debug-session-state session) '(detached error))
    (setf (disasm-debug-session-state session) 'exited))
  (ignore-errors (disasm-debug-pane--refresh session))
  (message "disasm: debugger for %s exited (%s)"
           (disasm-debug-session-name session) status))

;;; Commands

;;;###autoload
(defun disasm-attach (entry)
  "Attach to a running process and debug it.
ENTRY is a `disasm-proc-entry' chosen from the process list."
  (interactive (list (disasm-proc-read)))
  (let* ((session (disasm-debug-session--create
                   :backend disasm-debug-backend
                   :pid (disasm-proc-entry-pid entry)
                   :name (disasm-proc-entry-name entry)
                   :state 'connecting))
         (listing (get-buffer-create (disasm-debug--listing-name session))))
    (with-current-buffer listing
      (disasm-mode)
      (setq-local disasm--session (disasm-debug--placeholder-session session))
      (setq-local disasm-debug--session session)
      (setq-local disasm-debug--pc-overlay nil)
      (setq-local disasm-debug--laid-out nil)
      (disasm-render))
    (setf (disasm-debug-session-listing session) listing)
    (message "Attaching to %s (%d) ..."
             (disasm-debug-session-name session)
             (disasm-debug-session-pid session))
    (pcase (disasm-debug-session-backend session)
      ('gdb-mi
       (disasm-debug-gdb-start session)
       (disasm-debug-gdb-attach session (disasm-debug-session-pid session)))
      (_ (user-error "Unknown debugger backend: %s"
                     (disasm-debug-session-backend session))))
    session))

(defun disasm-debug-detach (session)
  "Detach SESSION's debugger from its target."
  (interactive (list (disasm-debug--current-session)))
  (setf (disasm-debug-session-state session) 'detached)
  (when (disasm-debug-session-live-file session)
    (ignore-errors (delete-file (disasm-debug-session-live-file session)))
    (setf (disasm-debug-session-live-file session) nil))
  (pcase (disasm-debug-session-backend session)
    ('gdb-mi (disasm-debug-gdb-detach session))))

(defun disasm-debug--run (operation)
  "Run OPERATION on the current buffer's debug session.
The session state is updated when the debugger reports the resulting
asynchronous `*running' or `*stopped' event."
  (let ((session (disasm-debug--current-session)))
    (pcase operation
      ('continue (disasm-debug-gdb-continue session))
      ('stepi (disasm-debug-gdb-stepi session))
      ('nexti (disasm-debug-gdb-nexti session))
      ('finish (disasm-debug-gdb-finish session))
      ('interrupt (disasm-debug-gdb-interrupt session)))))

(defun disasm-debug-continue ()
  "Resume execution of the debugged process (F5)."
  (interactive)
  (disasm-debug--run 'continue))

(defun disasm-debug-stepi ()
  "Step one instruction (F11)."
  (interactive)
  (disasm-debug--run 'stepi))

(defun disasm-debug-nexti ()
  "Step over one instruction (F10)."
  (interactive)
  (disasm-debug--run 'nexti))

(defun disasm-debug-finish ()
  "Run until the current function returns (S-F11)."
  (interactive)
  (disasm-debug--run 'finish))

(defun disasm-debug-interrupt ()
  "Interrupt the running debugged process."
  (interactive)
  (disasm-debug--run 'interrupt))

(defun disasm-debug--goto-address (session addr)
  "Show the live address ADDR in SESSION's listing."
  (let* ((module (disasm-debug-module-for-address
                  (disasm-debug-session-modules session) addr))
         (file (and module (disasm-debug-module-path module))))
    (cond
     ((and module file (equal file (disasm-debug-session-file session)))
      (disasm-debug--goto-live session addr))
     ((and module file (file-regular-p file))
      (disasm-debug--display-module session module addr))
     (t (disasm-debug--display-live session addr)))))

;;; Follow and go-to

(defun disasm-debug-goto (address)
  "Show the live ADDRESS in the debug listing.
When ADDRESS is not backed by a module file, its memory is read from
the target and disassembled."
  (interactive (list (read-string "Live address (hex): ")))
  (disasm-debug--goto-address (disasm-debug--current-session)
                              (disasm--hex-to-int address)))

(defun disasm-debug--operand-address (operands)
  "Return the resolved address embedded in OPERANDS, or nil.
objdump prints the effective address of a rip-relative memory operand
as a trailing `# 0x...' comment; both the `0x' prefix and its absence
are accepted."
  (when (and operands
             (string-match "#[ \t]*\\(?:0x\\)?\\([0-9a-fA-F]+\\)" operands))
    (string-to-number (match-string 1 operands) 16)))

(defun disasm-debug--follow-target (session)
  "Return the live address referenced by the instruction at point, or nil.
A direct branch or call target is preferred; otherwise the effective
address of a rip-relative memory operand is used."
  (when disasm--session
    (let* ((insn (disasm--insn-at-point))
           (delta (or (disasm-debug-session-delta session) 0)))
      (when insn
        (let ((target (or (disasm-insn-target insn)
                          (disasm-debug--operand-address
                           (disasm-insn-operands insn)))))
          (when target (+ target delta)))))))

(defun disasm-debug-follow ()
  "Follow the address at point.
In a state pane the value is dereferenced (following a pointer); in
the listing a direct branch target or the effective address of a
rip-relative operand is followed.  In an ordinary (non-debug) listing
this falls back to `forward-char'."
  (interactive)
  (let ((session (disasm-debug--maybe-session)))
    (cond
     ((null session)
      (if (derived-mode-p 'disasm-mode)
          (call-interactively #'forward-char)
        (user-error "Nothing to follow here")))
     ((derived-mode-p 'disasm-debug-pane-mode)
      (let ((addr (disasm-debug-pane--address-at-point)))
        (unless addr (user-error "No address on this line"))
        (let ((target (disasm-debug--read-pointer session addr)))
          (unless target
            (user-error "Cannot read memory at %s"
                        (disasm--format-address
                         addr (or (disasm-debug-session-bits session) 64))))
          (disasm-debug--goto-address session target))))
     ((derived-mode-p 'disasm-mode)
      (let ((target (disasm-debug--follow-target session)))
        (unless target (user-error "Nothing to follow at point"))
        (disasm-debug--goto-address session target)))
     (t (user-error "Nothing to follow here")))))

(defun disasm-debug--quit-buffers (session)
  "Return the list of buffers belonging to SESSION."
  (delq nil (list (disasm-debug-session-listing session)
                  (disasm-debug-session-registers-buffer session)
                  (disasm-debug-session-flags-buffer session)
                  (disasm-debug-session-stack-buffer session)
                  (disasm-debug-session-hex-buffer session))))

(provide 'disasm-debug)
;;; disasm-debug.el ends here
