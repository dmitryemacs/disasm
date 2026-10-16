;;; disasm-registers.el --- Debug state panes for disasm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://github.com/dmitryemacs/disasm

;;; Commentary:

;; The right-hand column of the debug layout: four read-only panes that
;; show the CPU registers, the flags, the threads and the call stack of
;; the debugged process.  They all share `disasm-debug-pane-mode' and
;; differ in the buffer-local value of `disasm-debug-pane-kind'.  Lines
;; that stand for an address jump the listing to that address; a thread
;; line switches the debugger to that thread and a frame line selects
;; that frame, which also moves the listing there.

;;; Code:

(require 'cl-lib)
(require 'subr-x)
(require 'disasm-core)
(require 'disasm-debug-core)

(declare-function disasm-debug--goto-address "disasm-debug" (session addr))
(declare-function disasm-debug-delete-breakpoint "disasm-debug" (session breakpoint))
(declare-function disasm-debug-select-frame "disasm-debug" (session level))
(declare-function disasm-debug-select-thread "disasm-debug" (session id))

(defvar-local disasm-debug-pane-kind 'registers
  "Which pane this buffer shows: `registers', `flags', `threads' or `stack'.")

(defvar-local disasm-debug-pane-session nil
  "The `disasm-debug-session' displayed in this pane.")

(defvar-local disasm-debug-pane-prev-registers nil
  "Registers from the previous render, used to highlight changes.")

(defconst disasm-debug-pane--register-order-64
  '("rax" "rbx" "rcx" "rdx" "rsi" "rdi" "rbp" "rsp"
    "r8" "r9" "r10" "r11" "r12" "r13" "r14" "r15" "rip")
  "Register display order for 64-bit targets.")

(defconst disasm-debug-pane--register-order-32
  '("eax" "ebx" "ecx" "edx" "esi" "edi" "ebp" "esp" "eip")
  "Register display order for 32-bit targets.")

;;; Keymaps

(defvar disasm-debug-pane-entry-map
  (let ((map (make-sparse-keymap)))
    (define-key map [mouse-1] #'disasm-debug-pane-mouse-goto)
    (define-key map [mouse-2] #'disasm-debug-pane-mouse-goto)
    map)
  "Keymap attached to clickable debug pane entries.")

(defvar disasm-debug-pane-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "RET") #'disasm-debug-pane-goto)
    (define-key map (kbd "n") #'disasm-debug-pane-next)
    (define-key map (kbd "p") #'disasm-debug-pane-prev)
    (define-key map (kbd "d") #'disasm-debug-pane-delete)
    map)
  "Keymap for `disasm-debug-pane-mode'.")

;;; Buffer lifecycle

(defun disasm-debug-pane--buffer-name (session kind)
  "Return the pane buffer name for SESSION and KIND."
  (format "*disasm-%s: %s (%d)*"
          (symbol-name kind)
          (or (disasm-debug-session-name session) "process")
          (or (disasm-debug-session-pid session) 0)))

(defun disasm-debug-pane--get-buffer (session kind)
  "Create (or recreate) and return the KIND pane buffer for SESSION."
  (let ((buffer (get-buffer-create
                 (disasm-debug-pane--buffer-name session kind))))
    (with-current-buffer buffer
      (disasm-debug-pane-mode)
      (setq-local disasm-debug-pane-session session)
      (setq-local disasm-debug-pane-kind kind)
      (setq-local disasm-debug-pane-prev-registers nil)
      (disasm-debug-pane--render session))
    (pcase kind
      ('registers (setf (disasm-debug-session-registers-buffer session) buffer))
      ('flags (setf (disasm-debug-session-flags-buffer session) buffer))
      ('threads (setf (disasm-debug-session-threads-buffer session) buffer))
      ('stack (setf (disasm-debug-session-stack-buffer session) buffer))
      ('breakpoints (setf (disasm-debug-session-breakpoints-buffer session) buffer)))
    buffer))

(defun disasm-debug-pane--refresh (session)
  "Re-render SESSION's pane buffers, keeping the cursor roughly in place."
  (when session
    (dolist (buffer (list (disasm-debug-session-registers-buffer session)
                          (disasm-debug-session-flags-buffer session)
                          (disasm-debug-session-threads-buffer session)
                          (disasm-debug-session-stack-buffer session)
                          (disasm-debug-session-breakpoints-buffer session)))
      (when (buffer-live-p buffer)
        (with-current-buffer buffer
          (let ((line (line-number-at-pos)))
            (disasm-debug-pane--render session)
            (goto-char (point-min))
            (forward-line (1- line))))))))

;;; Rendering

(defun disasm-debug-pane--insert-title (text)
  "Insert a pane title TEXT."
  (insert (propertize (concat text "\n") 'face 'disasm-debug-pane-title-face)))

(defun disasm-debug-pane--render (session)
  "Render SESSION into the current pane buffer."
  (let ((inhibit-read-only t))
    (erase-buffer)
    (pcase disasm-debug-pane-kind
      ('registers (disasm-debug-pane--render-registers session))
      ('flags (disasm-debug-pane--render-flags session))
      ('threads (disasm-debug-pane--render-threads session))
      ('stack (disasm-debug-pane--render-stack session))
      ('breakpoints (disasm-debug-pane--render-breakpoints session)))
    (goto-char (point-min))))

(defun disasm-debug-pane--register-order (session)
  "Return the register display order for SESSION."
  (if (eq (disasm-debug-session-bits session) 32)
      disasm-debug-pane--register-order-32
    disasm-debug-pane--register-order-64))

(defun disasm-debug-pane--render-registers (session)
  "Render SESSION's registers into the current buffer."
  (disasm-debug-pane--insert-title "registers")
  (let* ((registers (disasm-debug-session-registers session))
         (prev disasm-debug-pane-prev-registers)
         (order (disasm-debug-pane--register-order session))
         (width (cl-loop for name in order maximize (length name))))
    (if (null registers)
        (insert (propertize (format "%s\n" (disasm-debug-pane--empty-text session))
                            'face 'disasm-comment-face))
      (dolist (name order)
        (let ((value (cdr (assoc name registers))))
          (when value
            (let* ((changed (and prev
                                 (let ((old (assoc name prev)))
                                   (and old (not (equal (cdr old) value))))))
                   (start (point)))
              (insert (propertize (format (concat "%-" (number-to-string width) "s ") name)
                                  'face 'disasm-debug-register-name-face))
              (insert (propertize (format "%-20s" value)
                                  'face (if changed
                                            'disasm-debug-register-changed-face
                                          'disasm-address-face)))
              (add-text-properties
               start (line-end-position)
               (list 'disasm-debug-addr (disasm--hex-to-int value)
                     'disasm-debug-register name
                     'mouse-face 'highlight
                     'local-map disasm-debug-pane-entry-map
                     'help-echo "mouse-1: go to this address in the listing"))
              (insert "\n")))))
      (setq-local disasm-debug-pane-prev-registers registers))))

(defun disasm-debug-pane--render-flags (session)
  "Render SESSION's flags into the current buffer."
  (disasm-debug-pane--insert-title "flags")
  (let ((flags (disasm-debug-session-flags session)))
    (if (null flags)
        (insert (propertize (format "%s\n" (disasm-debug-pane--empty-text session))
                            'face 'disasm-comment-face))
      (dolist (entry (disasm-debug-flags))
        (let* ((name (nth 0 entry))
               (bit (nth 1 entry))
               (desc (nth 2 entry))
               (set (= 0 (logand flags (ash 1 bit)))))
          (insert (propertize (format "%-3s " name) 'face 'bold))
          (insert (propertize (if set "0" "1")
                              'face (if set
                                        'disasm-debug-flag-clear-face
                                      'disasm-debug-flag-set-face)))
          (insert (propertize (format "   %s" desc) 'face 'disasm-comment-face))
          (insert "\n"))))))

(defun disasm-debug-pane--render-stack (session)
  "Render SESSION's call stack into the current buffer."
  (disasm-debug-pane--insert-title "stack")
  (let ((frames (disasm-debug-session-frames session))
        (bits (or (disasm-debug-session-bits session) 64)))
    (if (null frames)
        (insert (propertize (format "%s\n" (disasm-debug-pane--empty-text session))
                            'face 'disasm-comment-face))
      (dolist (frame frames)
        (let* ((level (disasm-debug-frame-level frame))
               (addr (disasm-debug-frame-addr frame))
               (start (point))
               (current (= level (or (disasm-debug-session-current-frame
                                      session)
                                     0))))
          (insert (propertize (format "%s#%-2d " (if current ">" " ") level)
                              'face (if current
                                        'disasm-debug-frame-current-face
                                      'disasm-comment-face)))
          (insert (propertize (if addr (disasm--format-address addr bits) "?")
                              'face 'disasm-address-face))
          (insert "  ")
          (insert (propertize (or (disasm-debug-frame-func frame) "??")
                              'face 'disasm-symbol-face))
          (when (disasm-debug-frame-file frame)
            (insert (propertize (format "  (%s)" (disasm-debug-frame-file frame))
                                'face 'disasm-comment-face)))
          (when (and addr current)
            (add-text-properties start (line-end-position)
                                 '(face disasm-debug-frame-current-face)))
          (add-text-properties
           start (line-end-position)
           (list 'disasm-debug-frame level
                 'disasm-debug-addr addr
                 'mouse-face 'highlight
                 'local-map disasm-debug-pane-entry-map
                 'help-echo "mouse-1: select this frame"))
          (insert "\n"))))))

(defun disasm-debug-pane--render-threads (session)
  "Render SESSION's threads into the current buffer."
  (disasm-debug-pane--insert-title "threads")
  (let ((threads (disasm-debug-session-threads session))
        (current (disasm-debug-session-current-thread session)))
    (if (null threads)
        (insert (propertize (format "%s\n" (disasm-debug-pane--empty-text session))
                            'face 'disasm-comment-face))
      (dolist (thread threads)
        (let* ((id (disasm-debug-thread-id thread))
               (state (disasm-debug-thread-state thread))
               (active (and current (equal id current)))
               (start (point)))
          (insert (propertize (format "%s %-4s " (if active ">" " ") id)
                              'face (if active
                                        'disasm-debug-thread-current-face
                                      'disasm-comment-face)))
          (insert (propertize (format "%-8s" state)
                              'face (if (equal state "stopped")
                                        'disasm-debug-register-name-face
                                      'disasm-comment-face)))
          (insert " ")
          (insert (propertize (or (disasm-debug-thread-name thread)
                                  (disasm-debug-thread-target-id thread)
                                  "??")
                              'face 'disasm-symbol-face))
          (let ((target (disasm-debug-thread-target-id thread)))
            (when (and target (disasm-debug-thread-name thread))
              (insert (propertize (format "  (%s)" target)
                                  'face 'disasm-comment-face))))
          (add-text-properties
           start (line-end-position)
           (list 'disasm-debug-thread id
                 'mouse-face 'highlight
                 'local-map disasm-debug-pane-entry-map
                 'help-echo "mouse-1: switch to this thread"))
          (insert "\n"))))))

(defun disasm-debug-pane--render-breakpoints (session)
  "Render SESSION's breakpoints into the current buffer."
  (disasm-debug-pane--insert-title "breakpoints")
  (let ((breakpoints (disasm-debug-session-breakpoints session))
        (bits (or (disasm-debug-session-bits session) 64))
        (hit (disasm-debug-session-hit-breakpoint session))
        (stopped (eq (disasm-debug-session-state session) 'stopped)))
    (if (null breakpoints)
        (insert (propertize (format "%s\n" (disasm-debug-pane--empty-text session))
                            'face 'disasm-comment-face))
      (dolist (bp breakpoints)
        (let* ((number (disasm-debug-breakpoint-number bp))
               (addr (disasm-debug-breakpoint-addr bp))
               (enabled (disasm-debug-breakpoint-enabled bp))
               (current (and stopped (eql number hit)))
               (start (point)))
          (insert (propertize (format "%s%-3d " (if current ">" " ") number)
                              'face (if current
                                        'disasm-debug-breakpoint-hit-face
                                      'disasm-comment-face)))
          (when addr
            (insert (propertize (disasm--format-address addr bits)
                                'face 'disasm-address-face)))
          (insert "  ")
          (insert (propertize (or (disasm-debug-breakpoint-func bp)
                                  (and (disasm-debug-breakpoint-file bp)
                                       (format "%s:%s"
                                               (file-name-nondirectory
                                                (disasm-debug-breakpoint-file bp))
                                               (disasm-debug-breakpoint-line bp)))
                                  "")
                              'face 'disasm-symbol-face))
          (unless enabled
            (insert (propertize "  (disabled)" 'face 'disasm-comment-face)))
          (when (and addr (not current))
            (add-text-properties
             start (line-end-position)
             (list 'disasm-debug-addr addr
                   'mouse-face 'highlight
                   'local-map disasm-debug-pane-entry-map
                   'help-echo "mouse-1: show this breakpoint in the listing")))
          (add-text-properties start (line-end-position)
                               (list 'disasm-debug-breakpoint number))
          (insert "\n"))))))

(defun disasm-debug-pane--empty-text (session)
  "Return a placeholder line for an empty pane of SESSION."
  (pcase (disasm-debug-session-state session)
    ('connecting "connecting ...")
    ('running "running ...")
    ('exited "target exited")
    ('detached "detached")
    ('error (or (disasm-debug-session-error session) "error"))
    (_ "no data")))

(defun disasm-debug-pane--header-line ()
  "Return the header line for the current pane buffer."
  (condition-case nil
      (let ((session disasm-debug-pane-session))
        (concat
         " "
         (propertize (symbol-name disasm-debug-pane-kind) 'face 'bold)
         "  "
         (propertize (or (disasm-debug-session-name session) "") 'face 'bold)
         (format "  [%s]" (disasm-debug-session-state-label session))
         (let ((reason (disasm-debug-session-reason session)))
           (if reason (format "  %s" reason) ""))))
    (error "")))

;;; Navigation

(defun disasm-debug-pane--address-at-point ()
  "Return the address on the current pane line, or nil."
  (get-text-property (line-beginning-position) 'disasm-debug-addr))

(defun disasm-debug-pane--register-at-point ()
  "Return the register name on the current pane line, or nil."
  (get-text-property (line-beginning-position) 'disasm-debug-register))

(defun disasm-debug-pane--frame-at-point ()
  "Return the stack frame level on the current pane line, or nil."
  (get-text-property (line-beginning-position) 'disasm-debug-frame))

(defun disasm-debug-pane--thread-at-point ()
  "Return the thread id on the current pane line, or nil."
  (get-text-property (line-beginning-position) 'disasm-debug-thread))

(defun disasm-debug-pane--entry-at-point ()
  "Return non-nil when the current pane line stands for a selectable entry:
an address, a stack frame or a thread."
  (or (disasm-debug-pane--address-at-point)
      (disasm-debug-pane--frame-at-point)
      (disasm-debug-pane--thread-at-point)))

(defun disasm-debug-pane-goto ()
  "Act on the entry shown on the current pane line.
An address is shown in the listing; a stack frame is selected, which
makes the registers describe it and moves the listing to its address; a
thread becomes the current one, which does the same for its innermost
frame."
  (interactive)
  (let ((session disasm-debug-pane-session))
    (cond
     ((disasm-debug-pane--thread-at-point)
      (disasm-debug-select-thread
       session (disasm-debug-pane--thread-at-point)))
     ((disasm-debug-pane--frame-at-point)
      (disasm-debug-select-frame
       session (disasm-debug-pane--frame-at-point)))
     (t
      (let ((addr (disasm-debug-pane--address-at-point)))
        (unless addr (user-error "No address on this line"))
        (disasm-debug--goto-address session addr))))))

(defun disasm-debug-pane-mouse-goto (event)
  "Show the entry clicked with EVENT in the listing."
  (interactive "e")
  (mouse-set-point event)
  (disasm-debug-pane-goto))

(defun disasm-debug-pane-next ()
  "Move to the next selectable pane entry."
  (interactive)
  (let ((start (point))
        (found nil))
    (forward-line 1)
    (while (and (not found) (not (eobp)))
      (if (disasm-debug-pane--entry-at-point)
          (setq found t)
        (forward-line 1)))
    (unless found (goto-char start))))

(defun disasm-debug-pane-prev ()
  "Move to the previous selectable pane entry."
  (interactive)
  (let ((start (point))
        (found nil))
    (forward-line -1)
    (while (and (not found) (not (bobp)))
      (if (disasm-debug-pane--entry-at-point)
          (setq found t)
        (forward-line -1)))
    (unless found (goto-char start))))

(defun disasm-debug-pane--breakpoint-at-point ()
  "Return the breakpoint number on the current pane line, or nil."
  (get-text-property (line-beginning-position) 'disasm-debug-breakpoint))

(defun disasm-debug-pane-delete ()
  "Delete the breakpoint shown on the current line."
  (interactive)
  (unless (eq disasm-debug-pane-kind 'breakpoints)
    (user-error "Not in the breakpoints pane"))
  (let ((number (disasm-debug-pane--breakpoint-at-point)))
    (unless number (user-error "No breakpoint on this line"))
    (let ((bp (cl-find number (disasm-debug-session-breakpoints
                               disasm-debug-pane-session)
                       :key #'disasm-debug-breakpoint-number)))
      (unless bp (user-error "No such breakpoint"))
      (disasm-debug-delete-breakpoint disasm-debug-pane-session bp))))

;;; Mode

;;;###autoload
(define-derived-mode disasm-debug-pane-mode special-mode "Disasm-Debug"
  "Major mode for the `disasm' registers, flags, threads and stack panes.

\\{disasm-debug-pane-mode-map}"
  (setq-local truncate-lines t)
  (setq-local header-line-format '(:eval (disasm-debug-pane--header-line))))

(provide 'disasm-registers)
;;; disasm-registers.el ends here
