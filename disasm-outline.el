;;; disasm-outline.el --- Section/function sidebars for disasm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://github.com/dmitryemacs/disasm

;;; Commentary:

;; Two read-only sidebars that mirror x64dbg's right-hand column: a list of
;; the binary's sections and a list of its functions (symbols).  Selecting an
;; entry moves the disassembly listing to that address, which in turn drives
;; the hex pane through the usual synchronization.  The sidebars are created
;; by the docked layout in `disasm-open'.

;;; Code:

(require 'cl-lib)
(require 'subr-x)
(require 'disasm-core)

(defvar disasm--session nil
  "The `disasm-session' displayed in this buffer (declared in `disasm-mode').")

(declare-function disasm-goto-address "disasm-mode" (addr))
(declare-function disasm-sync--tick "disasm-hex" ())

(defvar-local disasm-outline-kind 'sections
  "Which list this sidebar shows: `sections' or `functions'.")

;;; Keymaps

(defvar disasm-outline-entry-map
  (let ((map (make-sparse-keymap)))
    (define-key map [mouse-1] #'disasm-outline-mouse-goto)
    (define-key map [mouse-2] #'disasm-outline-mouse-goto)
    map)
  "Keymap attached to clickable sidebar entries.")

(defvar disasm-outline-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "RET") #'disasm-outline-goto)
    (define-key map (kbd "n") #'disasm-outline-next)
    (define-key map (kbd "p") #'disasm-outline-prev)
    map)
  "Keymap for `disasm-outline-mode'.")

;;; Buffer lifecycle

(defun disasm-outline--buffer-name (file kind)
  "Return the sidebar buffer name for FILE and KIND."
  (format "*disasm-%s: %s*" (if (eq kind 'sections) "sections" "functions")
          (file-name-nondirectory file)))

(defun disasm-outline--get-buffer (session kind)
  "Create (or recreate) and return the KIND sidebar buffer for SESSION."
  (let ((buffer (get-buffer-create
                 (disasm-outline--buffer-name (disasm-session-file session)
                                              kind))))
    (with-current-buffer buffer
      (disasm-outline-mode)
      (setq-local disasm--session session)
      (setq-local disasm-outline-kind kind)
      (disasm-outline--render session))
    (pcase kind
      ('sections (setf (disasm-session-sections-buffer session) buffer))
      ('functions (setf (disasm-session-functions-buffer session) buffer)))
    buffer))

(defun disasm-outline--refresh (session)
  "Re-render SESSION's sidebar buffers, keeping the cursor roughly in place."
  (when session
    (dolist (buffer (list (disasm-session-sections-buffer session)
                          (disasm-session-functions-buffer session)))
      (when (buffer-live-p buffer)
        (with-current-buffer buffer
          (let ((line (line-number-at-pos)))
            (disasm-outline--render session)
            (goto-char (point-min))
            (forward-line (1- line))))))))

;;; Rendering

(defun disasm-outline--name-width (names)
  "Return a sensible column width for the symbol NAMES."
  (min 40 (max 8 (apply #'max 8 (mapcar #'length names)))))

(defun disasm-outline--insert-entry (name addr bits name-face width)
  "Insert a sidebar entry for NAME at ADDR.
BITS is the address width; NAME-FACE faces the name; WIDTH pads the
name column.  The whole line is made clickable and carries the
`disasm-outline-addr' property."
  (let ((start (point)))
    (insert (propertize (format (concat "%-" (number-to-string width) "s") name)
                        'face name-face))
    (insert "  ")
    (insert (propertize (if addr (disasm--format-address addr bits) "")
                        'face 'disasm-address-face))
    (add-text-properties start (line-end-position)
                         (list 'disasm-outline-addr addr
                               'mouse-face 'highlight
                               'local-map disasm-outline-entry-map
                               'help-echo "mouse-1: go to this address in the listing"))
    (insert "\n")))

(defun disasm-outline--functions (session)
  "Return SESSION's functions as an alist (NAME . ADDR).
Section names and local labels (leading dot) are filtered out."
  (let ((sections (disasm-session-sections session))
        (result nil))
    (dolist (symbol (disasm-session-symbols session))
      (let ((name (car symbol)))
        (unless (or (string-prefix-p "." name)
                    (cl-some (lambda (s) (equal name (disasm-section-name s)))
                             sections))
          (push symbol result))))
    (nreverse result)))

(defun disasm-outline--render-sections (session)
  "Render SESSION's sections into the current buffer."
  (let ((sections (disasm-session-sections session)))
    (if (null sections)
        (insert (propertize "no sections\n" 'face 'disasm-comment-face))
      (let ((bits (or (disasm-session-bits session) 64))
            (width (disasm-outline--name-width
                    (mapcar #'disasm-section-name sections))))
        (dolist (s sections)
          (disasm-outline--insert-entry (disasm-section-name s)
                                        (disasm-section-vma s)
                                        bits 'disasm-section-face width))))))

(defun disasm-outline--render-functions (session)
  "Render SESSION's functions into the current buffer."
  (let ((functions (disasm-outline--functions session)))
    (cond
     ((eq (disasm-session-state session) 'loading)
      (insert (propertize "disassembling ...\n" 'face 'disasm-comment-face)))
     ((null functions)
      (insert (propertize "no symbols\n" 'face 'disasm-comment-face)))
     (t
      (let ((bits (or (disasm-session-bits session) 64))
            (width (disasm-outline--name-width (mapcar #'car functions))))
        (dolist (f functions)
          (disasm-outline--insert-entry (car f) (cdr f)
                                        bits 'disasm-symbol-face width)))))))

(defun disasm-outline--render (session)
  "Render SESSION into the current sidebar buffer."
  (let ((inhibit-read-only t))
    (erase-buffer)
    (if (eq disasm-outline-kind 'sections)
        (disasm-outline--render-sections session)
      (disasm-outline--render-functions session))
    (goto-char (point-min))))

(defun disasm-outline--header-line ()
  "Return the header line for the current sidebar buffer."
  (condition-case nil
      (let ((session disasm--session))
        (concat
         " "
         (propertize (if (eq disasm-outline-kind 'sections)
                         "sections" "functions")
                     'face 'bold)
         "  "
         (propertize (file-name-nondirectory (disasm-session-file session))
                     'face 'bold)
         (cond ((eq (disasm-session-state session) 'loading) "  [disassembling ...]")
               ((eq (disasm-session-state session) 'error) "  [error]")
               (t ""))))
    (error "")))

;;; Navigation

(defun disasm-outline--address-at-point ()
  "Return the address on the current sidebar line, or nil."
  (get-text-property (line-beginning-position) 'disasm-outline-addr))

(defun disasm-outline--jump (session addr)
  "Show ADDR in SESSION's listing (and hex) panes."
  (let ((buffer (disasm-session-buffer session)))
    (unless (buffer-live-p buffer)
      (user-error "The disassembly listing is no longer available"))
    (let ((window (get-buffer-window buffer)))
      (if window
          (select-window window)
        (pop-to-buffer buffer)))
    (condition-case err
        (progn
          (with-current-buffer buffer
            (disasm-goto-address addr))
          (when (fboundp 'disasm-sync--tick)
            (disasm-sync--tick)))
      (user-error (message "%s" (error-message-string err))))))

(defun disasm-outline-goto ()
  "Go to the address on the current sidebar line in the listing."
  (interactive)
  (let ((addr (disasm-outline--address-at-point)))
    (unless addr (user-error "No address on this line"))
    (disasm-outline--jump disasm--session addr)))

(defun disasm-outline-mouse-goto (event)
  "Go to the sidebar entry clicked with EVENT."
  (interactive "e")
  (mouse-set-point event)
  (disasm-outline-goto))

(defun disasm-outline-next ()
  "Move to the next sidebar entry."
  (interactive)
  (let ((start (point))
        (found nil))
    (forward-line 1)
    (while (and (not found) (not (eobp)))
      (if (disasm-outline--address-at-point)
          (setq found t)
        (forward-line 1)))
    (unless found (goto-char start))))

(defun disasm-outline-prev ()
  "Move to the previous sidebar entry."
  (interactive)
  (let ((start (point))
        (found nil))
    (forward-line -1)
    (while (and (not found) (not (bobp)))
      (if (disasm-outline--address-at-point)
          (setq found t)
        (forward-line -1)))
    (unless found (goto-char start))))

;;; Mode

;;;###autoload
(define-derived-mode disasm-outline-mode special-mode "Disasm-Side"
  "Major mode for the `disasm' sidebar (sections or functions).

\\{disasm-outline-mode-map}"
  (setq-local truncate-lines t)
  (setq-local header-line-format '(:eval (disasm-outline--header-line))))

(provide 'disasm-outline)
;;; disasm-outline.el ends here
