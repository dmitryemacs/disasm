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
(require 'disasm-debug-core)
(require 'disasm-debug-gdb)
(require 'disasm-registers)
(require 'disasm-mode)
(require 'disasm-hex)
(require 'disasm-proc)

(declare-function disasm--build-session "disasm" (file &optional raw))
(declare-function disasm--split-fraction "disasm" (window fraction side))
(declare-function disasm-sync--tick "disasm-hex" ())
(declare-function disasm-goto-address "disasm-mode" (addr))
(declare-function disasm-hex--get-buffer "disasm-hex" (session))

;;; State

(defvar-local disasm-debug--session nil
  "The `disasm-debug-session' driving this listing buffer.")

(defvar-local disasm-debug--pc-overlay nil
  "Overlay marking the program counter in this listing buffer.")

(defvar-local disasm-debug--laid-out nil
  "Non-nil once the debug layout has been built for this buffer.")

(defun disasm-debug--current-session ()
  "Return the debug session of the current buffer, or signal an error."
  (cond
   ((bound-and-true-p disasm-debug--session) disasm-debug--session)
   ((bound-and-true-p disasm-debug-pane-session) disasm-debug-pane-session)
   (t (user-error "No debugging session in this buffer"))))

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

;;; Highlighting

(defun disasm-debug--refresh-pc-overlay ()
  "Re-apply the program-counter overlay in the current listing buffer.
Called after (re)rendering when the current buffer is a debug listing."
  (when (and (bound-and-true-p disasm-debug--session)
             (disasm-debug-session-pc disasm-debug--session))
    (disasm-debug--highlight-pc
     disasm-debug--session
     (disasm-debug--live-to-file disasm-debug--session
                                 (disasm-debug-session-pc disasm-debug--session)))))

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
          (setf (disasm-session-buffer dsession) listing)
          (disasm-render)
          (disasm--begin-disassembly dsession listing
                                     (disasm-debug--live-to-file session addr)))
        (disasm-debug--highlight-pc session (disasm-debug--live-to-file session addr))))))

(defun disasm-debug--show-pc (session)
  "Show the program counter of SESSION in its listing buffer."
  (let ((pc (disasm-debug-session-pc session)))
    (when pc
      (let ((module (disasm-debug-module-for-address
                     (disasm-debug-session-modules session) pc)))
        (cond
         ((null module)
          (message "disasm: pc %s is outside the known modules" (format "0x%x" pc)))
         ((not (and (disasm-debug-module-path module)
                    (file-regular-p (disasm-debug-module-path module))))
          (message "disasm: cannot read %s" (disasm-debug-module-path module)))
         (t (disasm-debug--display-module session module pc)))))))

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
            (stack (disasm-debug-pane--get-buffer session 'stack)))
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
          ;; Left column: the hex pane below the listing, when a file is known.
          (let ((dsession (disasm-debug--listing-session session)))
            (when (and dsession (disasm-session-file dsession)
                       (file-regular-p (disasm-session-file dsession)))
              (let* ((hexbuf (disasm-hex--get-buffer dsession))
                     (hexwin (disasm--split-fraction win
                                                     (/ disasm-hex-height 100.0)
                                                     'below)))
                (set-window-buffer hexwin hexbuf)
                (setf (disasm-session-hex-buffer dsession) hexbuf))))
          (select-window win)))
      (with-current-buffer listing
        (setq-local disasm-debug--laid-out t))
      (when (fboundp 'disasm-sync-mode)
        (disasm-sync-mode 1)
        (disasm-sync--tick)))))

;;; Refresh

(defun disasm-debug--ui-refresh (session)
  "Update SESSION's panes, listing and layout from its state."
  (condition-case err
      (progn
        (disasm-debug--show-pc session)
        (disasm-debug--ensure-layout session)
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
     (t (user-error "Address %s is outside the known modules"
                    (format "0x%x" addr))))))

(defun disasm-debug--quit-buffers (session)
  "Return the list of buffers belonging to SESSION."
  (delq nil (list (disasm-debug-session-listing session)
                  (disasm-debug-session-registers-buffer session)
                  (disasm-debug-session-flags-buffer session)
                  (disasm-debug-session-stack-buffer session))))

(provide 'disasm-debug)
;;; disasm-debug.el ends here
