;;; disasm-hex.el --- Hex pane and two-pane sync for disasm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://example.invalid/disasm

;;; Commentary:

;; A read-only hex dump of the whole file, laid out in file-offset order but
;; with an extra column showing the virtual address of each line (computed
;; from the section table).  It is designed to be displayed next to a
;; `disasm-mode' listing and kept in sync with it in both directions.

;;; Code:

(require 'cl-lib)
(require 'subr-x)
(require 'disasm-core)
(require 'disasm-mode)

(defvar-local disasm--hex-overlays nil
  "Overlays highlighting the current instruction's bytes in the hex pane.")
(defvar-local disasm--hex-prefix 0
  "Number of characters before the bytes column (offset + vaddr + padding).")
(defvar-local disasm--hex-buffer nil
  "In a `disasm-mode' buffer, the associated hex pane buffer.")
(defvar disasm--sync-inhibit nil
  "When non-nil, the sync hook does nothing (prevents feedback loops).")
(defvar disasm-sync-mode)

(defconst disasm-hex--byte-hex
  (let ((v (make-vector 256 nil)))
    (dotimes (i 256)
      (aset v i (format "%02x " i)))
    v)
  "Table mapping a byte value to its two-digit lowercase hex plus a space.")

(defconst disasm-hex--byte-ascii
  (let ((v (make-vector 256 nil)))
    (dotimes (i 256)
      (aset v i (if (and (>= i 32) (<= i 126)) (char-to-string i) ".")))
    v)
  "Table mapping a byte value to its printable ASCII representation.")

;;; Section mapping

(defun disasm--section-has-contents-p (section)
  "Return non-nil when SECTION actually occupies bytes in the file."
  (or (string-match-p "CONTENTS" (or (disasm-section-flags section) ""))
      (let ((fileoff (disasm-section-fileoff section)))
        (and (integerp fileoff) (> fileoff 0)))))

(defun disasm--content-sections (session)
  "Return the sections of SESSION that have file contents and an offset."
  (cl-remove-if-not (lambda (s)
                      (and (disasm--section-has-contents-p s)
                           (integerp (disasm-section-fileoff s))))
                    (disasm-session-sections session)))

(defun disasm--offset-to-vaddr (session offset)
  "Map file OFFSET to a virtual address using SESSION's sections."
  (let ((section (cl-find-if
                  (lambda (s)
                    (let ((fileoff (disasm-section-fileoff s)))
                      (and (integerp fileoff)
                           (<= fileoff offset)
                           (< offset (+ fileoff (disasm-section-size s))))))
                  (disasm--content-sections session))))
    (when section
      (+ (disasm-section-vma section)
         (- offset (disasm-section-fileoff section))))))

(defun disasm--vaddr-to-offset (session vaddr)
  "Map virtual address VADDR to a file offset using SESSION's sections."
  (let ((section (cl-find-if
                  (lambda (s)
                    (and (<= (disasm-section-vma s) vaddr)
                         (< vaddr (+ (disasm-section-vma s)
                                     (disasm-section-size s)))))
                  (disasm--content-sections session))))
    (when (and section (integerp (disasm-section-fileoff section)))
      (+ (disasm-section-fileoff section)
         (- vaddr (disasm-section-vma section))))))

(defun disasm--insn-file-offset (_session insn)
  "Return the file offset of INSN, or nil if it has no bytes."
  (let ((section (disasm-insn-section insn)))
    (when (and section
               (disasm--section-has-contents-p section)
               (integerp (disasm-section-fileoff section))
               (>= (disasm-insn-addr insn) (disasm-section-vma section)))
      (let ((offset (+ (disasm-section-fileoff section)
                       (- (disasm-insn-addr insn) (disasm-section-vma section)))))
        (when (< offset (+ (disasm-section-fileoff section)
                           (disasm-section-size section)))
          offset)))))

;;; Rendering

(defun disasm-hex--render (session)
  "Render the hex dump of SESSION's file into the current buffer."
  (let* ((file (disasm-session-file session))
         (bits (or (disasm-session-bits session) 64))
         (data (with-temp-buffer
                 (set-buffer-multibyte nil)
                 (insert-file-contents-literally file)
                 (buffer-string)))
         (total (length data))
         (limit (min total disasm-hex-max-bytes))
         (offw (max 8 (length (format "%x" (max 1 limit)))))
         (vw (if (> bits 32) 16 8))
         (prefix (+ offw 2 vw 2))
         (sections (sort (vconcat (disasm--content-sections session))
                         (lambda (a b)
                           (< (disasm-section-fileoff a)
                              (disasm-section-fileoff b)))))
         (nsec (length sections))
         (sidx 0)
         (data-format (concat "%0" (number-to-string offw) "x"))
         (vaddr-format (concat "%0" (number-to-string vw) "x")))
    (setq-local disasm--hex-prefix prefix)
    (setq-local disasm--hex-offset-width offw)
    (setq-local disasm--hex-vaddr-width vw)
    (let ((inhibit-read-only t)
          (off 0))
      (erase-buffer)
      (while (< off limit)
        ;; Move the section cursor forward.
        (while (and (< sidx nsec)
                    (<= (+ (disasm-section-fileoff (aref sections sidx))
                           (disasm-section-size (aref sections sidx)))
                        off))
          (setq sidx (1+ sidx)))
        (let* ((section (and (< sidx nsec) (aref sections sidx)))
               (vaddr (when (and section
                                 (<= (disasm-section-fileoff section) off)
                                 (< off (+ (disasm-section-fileoff section)
                                           (disasm-section-size section))))
                        (+ (disasm-section-vma section)
                           (- off (disasm-section-fileoff section)))))
               (end (min limit (+ off 16)))
               (i 0)
               (hexstr "")
               (asciistr ""))
          (while (< (+ off i) end)
            (let ((b (aref data (+ off i))))
              (setq hexstr (concat hexstr (aref disasm-hex--byte-hex b)))
              (setq asciistr (concat asciistr (aref disasm-hex--byte-ascii b))))
            (setq i (1+ i)))
          (while (< i 16)
            (setq hexstr (concat hexstr "   "))
            (setq i (1+ i)))
          (insert (concat
                   (propertize (format data-format off) 'face 'disasm-hex-offset-face)
                   "  "
                   (propertize (if vaddr (format vaddr-format vaddr)
                                 (make-string vw ?\s))
                               'face 'disasm-hex-vaddr-face)
                   "  "
                   (propertize hexstr 'face 'disasm-hex-bytes-face)
                   "  "
                   (propertize asciistr 'face 'disasm-hex-ascii-face)
                   "\n")))
        (setq off (+ off 16)))
      (when (< limit total)
        (insert (propertize
                 (format "\n;; hex truncated at 0x%x of 0x%x bytes (see `disasm-hex-max-bytes')\n"
                         limit total)
                 'face 'disasm-section-face)))
      (goto-char (point-min)))))

;;; Buffer lifecycle

(defun disasm-hex--buffer-name (file)
  "Return the hex pane buffer name for FILE."
  (format "*disasm-hex: %s*" (file-name-nondirectory file)))

(defun disasm-hex--get-buffer (session)
  "Create (or recreate) and return the hex pane buffer for SESSION."
  (let ((buffer (get-buffer-create
                 (disasm-hex--buffer-name (disasm-session-file session)))))
    (with-current-buffer buffer
      (disasm-hex-mode)
      (setq-local disasm--session session)
      (setq-local disasm--hex-overlays nil)
      (disasm-hex--render session))
    (setf (disasm-session-hex-buffer session) buffer)
    (let ((disasm-buffer (disasm-session-buffer session)))
      (when (buffer-live-p disasm-buffer)
        (with-current-buffer disasm-buffer
          (setq-local disasm--hex-buffer buffer))))
    buffer))

;;; Buffer positions

(defun disasm-hex--current-offset ()
  "Return the file offset at the beginning of the current line."
  (* 16 (1- (line-number-at-pos))))

(defun disasm--hex-highlight-bytes (buffer offset size)
  "Highlight SIZE bytes at file OFFSET in hex BUFFER."
  (when (buffer-live-p buffer)
    (with-current-buffer buffer
      (mapc #'delete-overlay disasm--hex-overlays)
      (setq disasm--hex-overlays nil)
      (when (and offset size (> size 0))
        (let ((pos offset)
              (fin (+ offset size))
              (prefix disasm--hex-prefix))
          (while (< pos fin)
            (let* ((line (1+ (/ pos 16)))
                   (index (% pos 16))
                   (segment (min (- 16 index) (- fin pos)))
                   (start (+ (disasm--line-start-pos line) prefix (* index 3)))
                   (end (+ start (* segment 3) -1))
                   (overlay (make-overlay start end)))
              (overlay-put overlay 'face 'disasm-hex-highlight-face)
              (push overlay disasm--hex-overlays)
              (setq pos (+ pos segment)))))))))

;;; Mode

(defvar disasm-hex-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "g") #'disasm-hex-goto)
    map)
  "Keymap for `disasm-hex-mode'.")

;;;###autoload
(define-derived-mode disasm-hex-mode special-mode "Disasm-Hex"
  "Major mode for the hex pane of `disasm'."
  (setq-local truncate-lines t)
  (setq-local header-line-format '(:eval (disasm-hex--header-line))))

(defun disasm-hex--header-line ()
  "Return the header line for the hex pane."
  (condition-case nil
      (let* ((session disasm--session)
             (offset (disasm-hex--current-offset))
             (vaddr (and session (disasm--offset-to-vaddr session offset))))
        (concat
         " hex "
         (propertize (file-name-nondirectory (disasm-session-file session)) 'face 'bold)
         (format "  off 0x%x" offset)
         (if vaddr
             (format "  vaddr %s"
                     (disasm--format-address vaddr (or (disasm-session-bits session) 64)))
           "")))
    (error "")))

(defun disasm-hex-goto (address)
  "Go to hexadecimal ADDRESS (a virtual address or a file offset)."
  (interactive (list (read-string "Address/offset (hex): ")))
  (unless disasm--session
    (user-error "No disasm session in this buffer"))
  (let* ((value (disasm--hex-to-int address))
         (offset (or (disasm--vaddr-to-offset disasm--session value) value))
         (line (1+ (/ offset 16))))
    (goto-char (point-min))
    (forward-line (1- line))))

;;; Two-pane synchronization

(defun disasm--insn-at-or-after-line (session line)
  "Return the first instruction of SESSION at or after LINE."
  (let* ((insns (disasm-session-insns session))
         (n (length insns))
         (idx (disasm-session-insn-index-at-line session line)))
    (cond
     ((zerop n) nil)
     ((null idx) (aref insns 0))
     ((= (disasm-insn-line (aref insns idx)) line) (aref insns idx))
     ((< (1+ idx) n) (aref insns (1+ idx)))
     (t (aref insns idx)))))

(defun disasm--sync-window (window buffer line)
  "Scroll WINDOW (displaying BUFFER) so that LINE is at the top."
  (let ((disasm--sync-inhibit t))
    (when (window-live-p window)
      (with-current-buffer buffer
        (let ((pos (disasm--line-start-pos line)))
          (set-window-point window pos)
          (set-window-start window pos))))))

(defun disasm--sync-highlight (session)
  "Update the hex highlight for SESSION based on the listing's point."
  (let ((hexbuf (disasm-session-hex-buffer session))
        (disasm-buffer (disasm-session-buffer session)))
    (when (and (buffer-live-p hexbuf) (buffer-live-p disasm-buffer))
      (let ((insn (with-current-buffer disasm-buffer
                    (when disasm--session
                      (disasm--insn-at-point)))))
        (if insn
            (let ((offset (disasm--insn-file-offset session insn)))
              (disasm--hex-highlight-bytes hexbuf offset
                                           (and offset (disasm-insn-size insn))))
          (disasm--hex-highlight-bytes hexbuf nil nil))))))

(defun disasm-sync--disasm-drives (session window)
  "Sync the hex pane from the listing WINDOW of SESSION."
  (disasm--sync-highlight session)
  (let* ((hexbuf (disasm-session-hex-buffer session))
         (hexwin (and (buffer-live-p hexbuf) (get-buffer-window hexbuf)))
         (line (with-current-buffer (window-buffer window)
                 (line-number-at-pos (window-point window))))
         (insn (disasm--insn-at-or-after-line session line))
         (offset (and insn (disasm--insn-file-offset session insn))))
    (when (and hexwin offset)
      (disasm--sync-window hexwin hexbuf (1+ (/ offset 16))))))

(defun disasm-sync--hex-drives (session window)
  "Sync the listing from the hex pane WINDOW of SESSION."
  (let* ((line (with-current-buffer (window-buffer window)
                 (line-number-at-pos (window-point window))))
         (offset (* 16 (1- line)))
         (vaddr (disasm--offset-to-vaddr session offset))
         (disasm-buffer (disasm-session-buffer session))
         (disasm-win (and (buffer-live-p disasm-buffer)
                          (get-buffer-window disasm-buffer)))
         (insns (disasm-session-insns session)))
    (when (and disasm-win vaddr (> (length insns) 0))
      (let* ((idx (disasm-session-insn-index-for-addr session vaddr))
             (target (disasm-insn-line (aref insns idx))))
        (disasm--sync-window disasm-win disasm-buffer target)))
    (disasm--sync-highlight session)))

(defun disasm-sync--tick ()
  "Synchronize the listing and its hex pane for the selected window."
  (when (and disasm-sync-mode (not disasm--sync-inhibit) (not (minibufferp)))
    (condition-case nil
        (let* ((window (selected-window))
               (buffer (window-buffer window))
               (session (buffer-local-value 'disasm--session buffer)))
          (when session
            (cond
             ((eq buffer (disasm-session-buffer session))
              (disasm-sync--disasm-drives session window))
             ((eq buffer (disasm-session-hex-buffer session))
              (disasm-sync--hex-drives session window)))))
      (error nil))))

;;;###autoload
(define-minor-mode disasm-sync-mode
  "Global minor mode keeping a `disasm-mode' buffer and its hex pane in sync.

When enabled, moving or scrolling in either the disassembly listing or
the hex pane scrolls the other to the same address, and the bytes of the
instruction at point are highlighted in the hex pane."
  :global t
  :lighter " Dsync"
  :group 'disasm
  (if disasm-sync-mode
      (add-hook 'post-command-hook #'disasm-sync--tick)
    (remove-hook 'post-command-hook #'disasm-sync--tick)))

(provide 'disasm-hex)
;;; disasm-hex.el ends here
