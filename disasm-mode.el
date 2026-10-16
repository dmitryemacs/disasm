;;; disasm-mode.el --- Major mode for disasm listings  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://example.invalid/disasm

;;; Commentary:

;; The read-only major mode used to present the disassembly listing,
;; together with navigation, xref and imenu integration.

;;; Code:

(require 'disasm-core)
(require 'disasm-objdump)
(require 'disasm-cache)
(require 'xref)
(require 'subr-x)

(defvar-local disasm--session nil
  "The `disasm-session' currently displayed in this buffer.")

(defvar disasm-target-map
  (let ((map (make-sparse-keymap)))
    (define-key map [mouse-1] #'disasm-mouse-follow)
    (define-key map [mouse-2] #'disasm-mouse-follow)
    map)
  "Keymap attached to clickable branch/call targets.")

;;; Keymap

(defvar disasm-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "n") #'disasm-next-instruction)
    (define-key map (kbd "p") #'disasm-prev-instruction)
    (define-key map (kbd "g") #'disasm-goto-address)
    (define-key map (kbd "a") #'disasm-goto-entry)
    (define-key map (kbd "RET") #'disasm-follow)
    (define-key map (kbd "b") #'disasm-toggle-bytes)
    (define-key map (kbd "D") #'disasm-toggle-all-sections)
    (define-key map (kbd "R") #'disasm-refresh)
    (define-key map (kbd "y") #'disasm-copy-address)
    (define-key map (kbd "w") #'disasm-copy-instruction)
    map)
  "Keymap for `disasm-mode'.")

;;; Rendering

(defun disasm--fontify-operands (insn)
  "Return the operand string of INSN with syntax faces applied."
  (let* ((operands (or (disasm-insn-operands insn) ""))
         (string (copy-sequence operands))
         (comment-start (and (string-match "#" string) (match-beginning 0))))
    ;; Registers.
    (let ((start 0))
      (while (and (not (and comment-start (>= start comment-start)))
                  (string-match disasm-register-regexp string start))
        (let ((beg (match-beginning 0)) (end (match-end 0)))
          (when (or (null comment-start) (< beg comment-start))
            (put-text-property beg end 'face 'disasm-register-face string)))
        (setq start (match-end 0))))
    ;; Immediates.
    (let ((start 0))
      (while (string-match "\\_<0x[0-9a-fA-F]+\\_>" string start)
        (let ((beg (match-beginning 0)) (end (match-end 0)))
          (when (or (null comment-start) (< beg comment-start))
            (put-text-property beg end 'face 'disasm-immediate-face string)))
        (setq start (match-end 0))))
    ;; Symbol references.
    (let ((start 0))
      (while (string-match "<[^>]+>" string start)
        (let ((beg (match-beginning 0)) (end (match-end 0)))
          (when (or (null comment-start) (< beg comment-start))
            (put-text-property beg end 'face 'disasm-symbol-face string)))
        (setq start (match-end 0))))
    ;; Comment (applied last so it wins).
    (when comment-start
      (put-text-property comment-start (length string) 'face 'disasm-comment-face string))
    ;; Clickable branch/call target.
    (when (disasm-insn-target insn)
      (let ((target (format "0x%x" (disasm-insn-target insn)))
            (start 0))
        (while (string-match (regexp-quote target) string start)
          (let ((beg (match-beginning 0)) (end (match-end 0)))
            (put-text-property beg end 'face 'disasm-target-face string)
            (put-text-property beg end 'mouse-face 'highlight string)
            (put-text-property beg end 'local-map disasm-target-map string)
            (put-text-property beg end 'help-echo "mouse-1: follow branch target" string))
          (setq start (match-end 0)))))
    string))

(defun disasm-render ()
  "Render the current session into the current buffer."
  (interactive)
  (let ((state (disasm-session-state disasm--session)))
    (cond
     ((eq state 'loading)
      (disasm--render-message
       (format ";;; disassembling %s ...\n"
               (file-name-nondirectory (disasm-session-file disasm--session)))))
     ((eq state 'error)
      (disasm--render-message
       (format ";;; disassembly failed: %s\n"
               (or (disasm-session-error disasm--session) "unknown error"))))
     (t (disasm--render-insns)))))

(defun disasm--render-message (text)
  "Replace the buffer contents with the read-only message TEXT."
  (let ((inhibit-read-only t))
    (erase-buffer)
    (insert (propertize text 'face 'disasm-section-face))
    (goto-char (point-min))))

(defun disasm--render-insns ()
  "Render the instructions of the current session into this buffer."
  (let* ((session disasm--session)
         (insns (disasm-session-insns session))
         (bits (or (disasm-session-bits session) 64))
         (show-bytes (disasm-session-show-bytes session))
         (fontify (or (null disasm-fontify-limit)
                      (<= (length insns) disasm-fontify-limit)))
         (bytes-width 20))
    (when show-bytes
      (dotimes (i (length insns))
        (setq bytes-width
              (max bytes-width (length (or (disasm-insn-bytes (aref insns i)) ""))))))
    (let ((inhibit-read-only t)
          (buffer-undo-list t)
          (inhibit-modification-hooks t)
          (cur-section 'none)
          (line 1))
      (erase-buffer)
      (dotimes (i (length insns))
        (let* ((insn (aref insns i))
               (sec (disasm-insn-section insn)))
          (unless (eq sec cur-section)
            (setq cur-section sec)
            (insert (propertize
                     (format ";;; %s%s @ %s  size 0x%x\n"
                             (if (and sec (disasm-section-code-p sec)) "code " "")
                             (if sec (disasm-section-name sec) "<unknown>")
                             (if sec (disasm--format-address (disasm-section-vma sec) bits) "?")
                             (if sec (disasm-section-size sec) 0))
                     'face 'disasm-section-face))
            (setq line (1+ line)))
          (when (disasm-insn-label insn)
            (insert (propertize (format "%s:\n" (disasm-insn-label insn))
                                'face 'disasm-label-face))
            (setq line (1+ line)))
          (setf (disasm-insn-line insn) line)
          (insert (propertize (disasm--plain-address (disasm-insn-addr insn) bits)
                              'face 'disasm-address-face))
          (insert "  ")
          (when show-bytes
            (insert (propertize
                     (format (concat "%-" (number-to-string bytes-width) "s")
                             (or (disasm-insn-bytes insn) ""))
                     'face 'disasm-bytes-face))
            (insert "  "))
          (insert (propertize (format "%-8s" (disasm-insn-mnemonic insn))
                              'face 'disasm-mnemonic-face))
          (insert (if fontify
                      (disasm--fontify-operands insn)
                    (or (disasm-insn-operands insn) "")))
          (insert "\n")
          (setq line (1+ line))))
      (goto-char (point-min)))))

;;; Mode

;;;###autoload
(define-derived-mode disasm-mode special-mode "Disasm"
  "Major mode for browsing disassembly produced by `disasm'.

\\{disasm-mode-map}"
  (setq-local truncate-lines t)
  (setq-local imenu-create-index-function #'disasm--imenu-index)
  (setq-local header-line-format '(:eval (disasm--header-line)))
  (setq-local revert-buffer-function #'disasm-refresh)
  (when (fboundp 'hl-line-mode)
    (hl-line-mode 1)))

;;; Point helpers

(defun disasm--insn-at-point ()
  "Return the instruction on the current line, or nil."
  (when disasm--session
    (let ((idx (disasm-session-insn-index-at-line disasm--session (line-number-at-pos))))
      (when idx
        (aref (disasm-session-insns disasm--session) idx)))))

(defun disasm--line-is-insn-p (session line)
  "Return non-nil when LINE holds an instruction in SESSION."
  (let ((idx (disasm-session-insn-index-at-line session line)))
    (and idx (= (disasm-insn-line (aref (disasm-session-insns session) idx)) line))))

(defun disasm--line-start-pos (line)
  "Return the buffer position at the beginning of LINE."
  (save-excursion
    (goto-char (point-min))
    (forward-line (1- line))
    (point)))

(defun disasm--current-address ()
  "Return the address of the instruction at point, or nil."
  (let ((insn (disasm--insn-at-point)))
    (when insn (disasm-insn-addr insn))))

(defun disasm--read-address ()
  "Read a hexadecimal address from the minibuffer."
  (let* ((insn (disasm--insn-at-point))
         (default (and insn (format "0x%x" (disasm-insn-addr insn))))
         (input (read-string (format-prompt "Address (hex)" default))))
    (if (string-empty-p input)
        (or default (user-error "No address given"))
      input)))

;;; Navigation commands

(defun disasm-next-instruction (&optional arg)
  "Move point to the next instruction.
With ARG, move that many instructions forward."
  (interactive "p")
  (let ((session disasm--session))
    (dotimes (_ (or arg 1))
      (let ((found nil))
        (while (and (not found) (not (eobp)))
          (forward-line 1)
          (when (disasm--line-is-insn-p session (line-number-at-pos))
            (setq found t)))
        (unless found (forward-line -1))))))

(defun disasm-prev-instruction (&optional arg)
  "Move point to the previous instruction.
With ARG, move that many instructions backward."
  (interactive "p")
  (let ((session disasm--session))
    (dotimes (_ (or arg 1))
      (let ((found nil))
        (while (and (not found) (not (bobp)))
          (forward-line -1)
          (when (disasm--line-is-insn-p session (line-number-at-pos))
            (setq found t)))
        (unless found (forward-line 1))))))

(defun disasm-goto-address (addr)
  "Move point to the instruction covering the hexadecimal address ADDR."
  (interactive (list (disasm--read-address)))
  (let* ((session disasm--session)
         (bits (disasm-session-bits session))
         (int (cl-etypecase addr
                (integer addr)
                (string (disasm--hex-to-int addr))))
         (insns (disasm-session-insns session))
         (idx (disasm-session-insn-index-for-addr session int)))
    (if (or (null idx) (zerop (length insns)))
        (user-error "Address %s is not covered by the listing"
                    (disasm--format-address int bits))
      (goto-char (point-min))
      (forward-line (1- (disasm-insn-line (aref insns idx))))
      (when (get-buffer-window (current-buffer) t)
        (recenter)))))

(defun disasm-goto-entry ()
  "Move point to the entry point of the current binary."
  (interactive)
  (let ((entry (and disasm--session (disasm-session-entry disasm--session))))
    (if entry
        (disasm-goto-address entry)
      (message "No entry point available"))))

(defun disasm-follow ()
  "Follow the direct branch or call target at point."
  (interactive)
  (let ((insn (disasm--insn-at-point)))
    (if (and insn (disasm-insn-target insn))
        (disasm-goto-address (disasm-insn-target insn))
      (user-error "No direct branch or call target at point"))))

(defun disasm-mouse-follow (event)
  "Follow the branch target clicked with EVENT."
  (interactive "e")
  (mouse-set-point event)
  (disasm-follow))

;;; Session commands

(defun disasm-toggle-bytes ()
  "Show or hide the raw bytes column."
  (interactive)
  (unless disasm--session (user-error "No disasm session in this buffer"))
  (let ((addr (disasm--current-address)))
    (setf (disasm-session-show-bytes disasm--session)
          (not (disasm-session-show-bytes disasm--session)))
    (disasm-render)
    (when addr (ignore-errors (disasm-goto-address addr)))))

(defun disasm-toggle-all-sections ()
  "Toggle between disassembling code sections and all sections."
  (interactive)
  (unless disasm--session (user-error "No disasm session in this buffer"))
  (setf (disasm-session-all-sections disasm--session)
        (not (disasm-session-all-sections disasm--session)))
  (disasm-reload))

;;; Asynchronous loading

(defun disasm--apply-result (session parsed)
  "Copy the parsed disassembly PARSED into SESSION and mark it ready."
  (setf (disasm-session-insns session) (or (plist-get parsed :insns) []))
  (setf (disasm-session-symbols session) (plist-get parsed :labels))
  (setf (disasm-session-error session) nil)
  (setf (disasm-session-state session) 'ready))

(defun disasm--begin-disassembly (session buffer &optional address force)
  "Start (or restart) disassembling SESSION and render it into BUFFER.
When ADDRESS is non-nil, move point there once the listing is ready.
Unless FORCE is non-nil, a cached result is reused when available."
  (let ((key (disasm-cache-key (disasm-session-file session)
                               (disasm-session-raw session)
                               (disasm-session-all-sections session))))
    (let ((cached (and (not force) (disasm-cache-get key))))
      (cond
       (cached
        (disasm--apply-result session cached)
        (when (buffer-live-p buffer)
          (with-current-buffer buffer
            (disasm-render)
            (when address (ignore-errors (disasm-goto-address address)))
            (disasm--sync-if-available))))
       (t
        (setf (disasm-session-state session) 'loading)
        (setf (disasm-session-error session) nil)
        (when (buffer-live-p buffer)
          (with-current-buffer buffer
            (disasm-render)
            (disasm--sync-if-available)))
        (disasm-objdump-disassemble-async
         (disasm-session-file session)
         (disasm-session-sections session)
         (disasm-session-all-sections session)
         (disasm-session-raw session)
         (lambda (status parsed)
           (when (buffer-live-p buffer)
             (with-current-buffer buffer
               (if (and (integerp status) (zerop status) parsed)
                   (progn
                     (disasm--apply-result session parsed)
                     (disasm-cache-put key parsed)
                     (disasm-render)
                     (when address (ignore-errors (disasm-goto-address address)))
                     (disasm--sync-if-available))
                 (setf (disasm-session-state session) 'error)
                 (setf (disasm-session-error session)
                       (format "objdump exited with status %s" status))
                 (disasm-render)
                 (disasm--sync-if-available)))))))))))

(defun disasm--sync-if-available ()
  "Refresh the two-pane synchronization when `disasm-hex' is loaded."
  (when (fboundp 'disasm-sync--tick)
    (disasm-sync--tick)))

(defun disasm-reload (&optional force)
  "Re-run objdump for the current session and redisplay.
Unless FORCE is non-nil, a cached result is reused when available."
  (interactive)
  (unless disasm--session (user-error "No disasm session in this buffer"))
  (disasm--begin-disassembly disasm--session (current-buffer)
                             (disasm--current-address) force))

(defun disasm-refresh (&optional _ignore-auto _noconfirm)
  "Re-run objdump and refresh the current disassembly listing."
  (interactive)
  (when disasm--session (disasm-reload 'force)))

(defun disasm-copy-address ()
  "Copy the address at point to the kill ring."
  (interactive)
  (let ((insn (disasm--insn-at-point)))
    (if insn
        (let ((text (format "0x%x" (disasm-insn-addr insn))))
          (kill-new text)
          (message "Copied %s" text))
      (user-error "No instruction at point"))))

(defun disasm-copy-instruction ()
  "Copy the instruction at point to the kill ring."
  (interactive)
  (let ((insn (disasm--insn-at-point)))
    (if insn
        (let ((text (string-trim (concat (disasm-insn-mnemonic insn) " "
                                         (disasm-insn-operands insn)))))
          (kill-new text)
          (message "Copied %s" text))
      (user-error "No instruction at point"))))

;;; Header line

(defun disasm--header-line ()
  "Return the mode header line for the current buffer."
  (condition-case nil
      (let* ((session disasm--session)
             (state (disasm-session-state session))
             (insn (disasm--insn-at-point))
             (bits (or (disasm-session-bits session) 64))
             (sec (and insn (disasm-insn-section insn))))
        (concat
         " "
         (propertize (file-name-nondirectory (disasm-session-file session)) 'face 'bold)
         (format "  %s / %s  "
                 (or (disasm-session-format session) "?")
                 (or (disasm-session-arch session) "?"))
         (if (disasm-session-raw session) "[raw]  " "")
         (format "%s  " (if (disasm-session-show-bytes session) "bytes" "no-bytes"))
         (propertize (if insn
                         (disasm--format-address (disasm-insn-addr insn) bits)
                       "??")
                     'face 'disasm-address-face)
         (if sec (format "  %s" (disasm-section-name sec)) "")
         (cond ((eq state 'loading) "  [disassembling ...]")
               ((eq state 'error) "  [error]")
               (t ""))))
    (error "")))

;;; Imenu

(defun disasm--imenu-index ()
  "Build the imenu index for the current session."
  (let ((insns (disasm-session-insns disasm--session))
        (sections (disasm-session-sections disasm--session))
        (labels (disasm-session-symbols disasm--session))
        (sec-items nil)
        (fn-items nil)
        (last-section 'none))
    (dotimes (i (length insns))
      (let* ((insn (aref insns i))
             (sec (disasm-insn-section insn)))
        (unless (eq sec last-section)
          (setq last-section sec)
          (when sec
            (push (cons (disasm-section-name sec)
                        (disasm--line-start-pos (disasm-insn-line insn)))
                  sec-items)))))
    (dolist (label labels)
      (let ((name (car label)))
        (unless (or (string-prefix-p "." name)
                    (cl-some (lambda (s) (equal name (disasm-section-name s))) sections))
          (let ((idx (disasm-session-insn-index-for-addr disasm--session (cdr label))))
            (when (and idx (= (disasm-insn-addr (aref insns idx)) (cdr label)))
              (push (cons name (disasm--line-start-pos
                                (disasm-insn-line (aref insns idx))))
                    fn-items))))))
    (let ((result nil))
      (when fn-items (push (cons "Functions" (nreverse fn-items)) result))
      (when sec-items (push (cons "Sections" (nreverse sec-items)) result))
      result)))

;;; Xref

(defun disasm-xref-backend ()
  "Register `disasm' as an xref backend inside `disasm-mode'."
  (when (derived-mode-p 'disasm-mode) 'disasm))

(add-hook 'xref-backend-functions #'disasm-xref-backend)

(cl-defmethod xref-backend-identifier-at-point ((_backend (eql disasm)))
  "Return the branch target at point as an xref identifier."
  (let ((insn (disasm--insn-at-point)))
    (when (and insn (disasm-insn-target insn))
      (format "0x%x" (disasm-insn-target insn)))))

(cl-defmethod xref-backend-definitions ((_backend (eql disasm)) identifier)
  "Return the definition location for IDENTIFIER."
  (let* ((session disasm--session)
         (addr (condition-case nil (disasm--hex-to-int identifier) (error nil)))
         (idx (and session addr
                   (disasm-session-insn-index-for-addr session addr))))
    (when (and idx (disasm-session-insns session)
               (>= (length (disasm-session-insns session)) 1))
      (let ((insn (aref (disasm-session-insns session) idx)))
        (list (xref-make
               (format "%s" identifier)
               (xref-make-buffer-location
                (current-buffer)
                (disasm--line-start-pos (disasm-insn-line insn)))))))))

(provide 'disasm-mode)
;;; disasm-mode.el ends here
