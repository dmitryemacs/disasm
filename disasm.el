;;; disasm.el --- Interactive disassembler for Emacs  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://example.invalid/disasm

;;; Commentary:

;; `disasm' is a front-end for an external disassembler (GNU objdump).
;; It reads a binary (PE/EXE, ELF, Mach-O, ...), runs objdump on it and
;; presents the result in a read-only listing buffer with syntax
;; highlighting, instruction-level navigation, xref and imenu support.
;;
;; Entry points:
;;
;;   M-x disasm-file     disassemble a file (single listing pane)
;;   M-x disasm-buffer   disassemble the file visited by the current buffer
;;   M-x disasm-open     disassemble a file with a synchronized hex pane
;;   M-x disasm-open-raw disassemble a headerless (raw) binary
;;   M-x disasm-open-hex open a hex pane for the current listing
;;   M-x disasm-cache-clear  forget cached disassembly results
;;
;; Disassembly runs asynchronously; the listing fills in when objdump
;; finishes.  Parsed results are cached in memory, so re-opening a file
;; or toggling options is instant.
;;
;; Key bindings inside the listing (`disasm-mode'):
;;
;;   n / p     next / previous instruction
;;   g         go to a hexadecimal address
;;   a         go to the entry point
;;   RET       follow a direct call/jump target
;;   b         toggle the raw bytes column
;;   D         toggle all-sections mode
;;   R         refresh
;;   y / w     copy address / instruction
;;
;; When `disasm-bind-prefix' is non-nil (the default), the commands are
;; also reachable through the \"C-c d\" prefix.

;;; Code:

(require 'disasm-core)
(require 'disasm-backend)
(require 'disasm-image)
(require 'disasm-cache)
(require 'disasm-mode)
(require 'disasm-hex)
(require 'disasm-outline)
(require 'disasm-debug)
(require 'disasm-mcp)

(defvar disasm-prefix-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "f") #'disasm-file)
    (define-key map (kbd "b") #'disasm-buffer)
    (define-key map (kbd "o") #'disasm-open)
    (define-key map (kbd "r") #'disasm-open-raw)
    (define-key map (kbd "h") #'disasm-open-hex)
    (define-key map (kbd "s") #'disasm-sync-mode)
    (define-key map (kbd "a") #'disasm-attach)
    (define-key map (kbd "R") #'disasm-debug-run)
    (define-key map (kbd "t") #'disasm-debug-toggle-breakpoint)
    (define-key map (kbd "B") #'disasm-debug-breakpoints)
    (define-key map (kbd "T") #'disasm-debug-threads)
    (define-key map (kbd "L") #'disasm-mcp-log)
    (define-key map (kbd "X") #'disasm-debug-clear-breakpoints)
    (define-key map (kbd "g") #'disasm-debug-goto)
    (define-key map (kbd "f") #'disasm-debug-follow)
    (define-key map (kbd "i") #'disasm-debug-interrupt)
    (define-key map (kbd "e") #'disasm-debug-edit)
    (define-key map (kbd "w") #'disasm-debug-write-memory)
    (define-key map (kbd "E") #'disasm-debug-set-register)
    (define-key map (kbd "c") #'disasm-cache-clear)
    map)
  "Command prefix map for `disasm', bound to \"C-c d\".")

(defun disasm--bits-from-header (header)
  "Guess the address width in bits from HEADER."
  (let ((format (or (plist-get header :format) ""))
        (arch (or (plist-get header :arch) "")))
    (if (or (string-match-p "64" format) (string-match-p "64" arch)) 64 32)))

(defun disasm--buffer-name (file)
  "Return the disasm buffer name for FILE."
  (format "*disasm: %s*" (file-name-nondirectory file)))

(defun disasm--build-session (file &optional raw)
  "Read FILE's header and sections and return a `disasm-session'.
The (slow) disassembly itself is not run here; the returned session has
state `loading' and is filled in asynchronously.  When RAW is non-nil,
FILE is treated as a headerless binary."
  (let* ((header (disasm-backend-header file raw))
         (sections (disasm-backend-sections file raw))
         (image (unless raw (disasm-image-info file)))
         (entry (plist-get header :entry)))
    ;; llvm-objdump's section table has no file offsets; recover them from
    ;; the PE/ELF container so the hex pane can stay in sync.
    (when image
      (disasm-image-fill-offsets image sections))
    ;; llvm-objdump reports no entry point for PE files; fall back to the
    ;; value read from the container header.
    (let ((image-entry (and image (plist-get image :entry))))
      (when (or (null entry) (zerop entry))
        (when (and image-entry (not (zerop image-entry)))
          (setq entry image-entry))))
    (disasm-session--create
     :file file
     :format (plist-get header :format)
     :arch (plist-get header :arch)
     :bits (disasm--bits-from-header header)
     :backend disasm-backend
     :sections sections
     :insns []
     :symbols nil
     :entry entry
     :show-bytes disasm-show-bytes
     :all-sections (or raw disasm-disassemble-all)
     :raw raw
     :state 'loading)))

(defun disasm--open (file &optional two-pane raw)
  "Disassemble FILE and display the result.
When TWO-PANE is non-nil, use the docked layout: the hex pane below the
listing and the section/function sidebars in a right-hand column.
When RAW is non-nil, treat FILE as a headerless binary."
  (unless (file-regular-p file)
    (user-error "Not a regular file: %s" file))
  (when (and raw (not (disasm-backend-supports-raw-p)))
    (user-error "The %s backend cannot disassemble raw binaries"
                (disasm-backend-name)))
  (message "Disassembling %s..." file)
  (let* ((session (disasm--build-session file raw))
         (buffer (get-buffer-create (disasm--buffer-name file))))
    (with-current-buffer buffer
      (disasm-mode)
      (setq-local disasm--session session)
      (setf (disasm-session-buffer session) buffer)
      (disasm-render))
    (if two-pane
        (disasm--open-docked session buffer)
      (pop-to-buffer buffer)
      ;; A single pane takes over the frame too.
      (disasm--collapse-other-windows
       (or (get-buffer-window buffer) (selected-window))))
    (disasm--begin-disassembly session buffer
                               (disasm-session-entry session))
    buffer))

(defun disasm--split-fraction (window fraction side)
  "Split WINDOW on SIDE, giving the new window FRACTION of its size.
FRACTION is a number between 0 and 1.  `split-window' interprets a
positive SIZE as the size the *original* window keeps, so we convert."
  (let* ((horizontal (memq side '(left right)))
         (total (if horizontal (window-width window) (window-height window)))
         (new (max 1 (round (* total fraction))))
         (keep (max 1 (- total new))))
    (split-window window keep side)))

(defun disasm--open-docked (session buffer)
  "Display SESSION's listing BUFFER in the docked, x64dbg-like layout.
The right column stacks the sections and functions sidebars; the hex
pane sits below the listing in the left column."
  (let ((hexbuf (disasm-hex--get-buffer session))
        (secbuf (disasm-outline--get-buffer session 'sections))
        (fnbuf (disasm-outline--get-buffer session 'functions)))
    (pop-to-buffer buffer)
    (let ((disasm-win (or (get-buffer-window buffer) (selected-window))))
      ;; The docked layout owns the frame.
      (disasm--collapse-other-windows disasm-win)
      (let* (;; Right column: sections on top, functions below.
             (outwin (disasm--split-fraction disasm-win
                                             (/ disasm-outline-width 100.0)
                                             'right))
             (fnwin (disasm--split-fraction outwin
                                            (- 1 (/ disasm-outline-split 100.0))
                                            'below)))
        (set-window-buffer outwin secbuf)
        (set-window-buffer fnwin fnbuf)
        ;; Left column: the hex pane below the listing.
        (let ((hexwin (disasm--split-fraction disasm-win
                                              (/ disasm-hex-height 100.0)
                                              'below)))
          (set-window-buffer hexwin hexbuf))
        (select-window disasm-win)))
    (disasm-sync-mode 1)
    (disasm-sync--tick)
    buffer))

(defun disasm--open-hex-pane (session buffer)
  "Display SESSION's BUFFER with a hex pane on the left.
Used by `disasm-open-hex', which also works for listings opened as a
single pane."
  (let ((hexbuf (disasm-hex--get-buffer session)))
    (pop-to-buffer buffer)
    (let ((disasm-win (or (get-buffer-window buffer) (selected-window))))
      ;; The two panes take over the frame.
      (disasm--collapse-other-windows disasm-win)
      (let ((hexwin (split-window disasm-win nil 'left)))
        (set-window-buffer hexwin hexbuf)
        (select-window disasm-win)))
    (disasm-sync-mode 1)
    (disasm-sync--tick)
    hexbuf))

;;;###autoload
(defun disasm-file (file)
  "Disassemble FILE and show the result."
  (interactive (list (read-file-name "Disassemble file: " nil nil t)))
  (disasm--open (expand-file-name file)))

;;;###autoload
(defun disasm-open (file)
  "Disassemble FILE and show it in the docked layout.
The listing sits at the top-left with a synchronized hex pane below it;
the binary's sections and functions fill a right-hand column."
  (interactive (list (read-file-name "Disassemble file: " nil nil t)))
  (disasm--open (expand-file-name file) t))

;;;###autoload
(defun disasm-open-raw (file arch base)
  "Disassemble FILE as a headerless binary.
ARCH is the target architecture passed to objdump (for example
\"i386:x86-64\") and BASE is the virtual address the first byte is
assumed to live at."
  (interactive
   (list (read-file-name "Raw binary: " nil nil t)
         (read-string (format-prompt "Architecture" disasm-raw-arch)
                      nil nil disasm-raw-arch)
         (disasm--hex-to-int
          (read-string (format-prompt "Base address (hex)"
                                      (format "0x%x" disasm-raw-base))
                       nil nil (format "0x%x" disasm-raw-base)))))
  (disasm--open (expand-file-name file) nil (list :arch arch :base base)))

;;;###autoload
(defun disasm-open-hex ()
  "Open a synchronized hex pane for the current `disasm-mode' listing."
  (interactive)
  (unless (derived-mode-p 'disasm-mode)
    (user-error "Not a disasm listing buffer"))
  (unless disasm--session
    (user-error "No disasm session in this buffer"))
  (disasm--open-hex-pane disasm--session (current-buffer)))

;;;###autoload
(defun disasm-buffer ()
  "Disassemble the file visited by the current buffer."
  (interactive)
  (let ((file (buffer-file-name)))
    (cond
     (file (disasm-file file))
     ((y-or-n-p "Buffer is not visiting a file; write it to a temporary file? ")
      (let ((tmp (make-temp-file "disasm-" nil ".bin")))
        (write-region (point-min) (point-max) tmp nil 'silent)
        (disasm-file tmp)))
     (t (user-error "No file to disassemble")))))

;;; Quitting

(defun disasm-quit ()
  "Close the current session's listing, hex and sidebar buffers.
Detaches from a debugged process first.  Bound to \\`q' in every
`disasm' buffer."
  (interactive)
  (let* ((debug (cond ((bound-and-true-p disasm-debug--session) disasm-debug--session)
                      ((bound-and-true-p disasm-debug-pane-session) disasm-debug-pane-session)))
         (session disasm--session)
         (buffers nil))
    (when debug
      (ignore-errors (disasm-debug-detach debug)))
    (setq buffers
          (delq nil
                (append
                 (list (current-buffer)
                       (and session (disasm-session-buffer session))
                       (and session (disasm-session-hex-buffer session))
                       (and session (disasm-session-sections-buffer session))
                       (and session (disasm-session-functions-buffer session)))
                 (and debug (disasm-debug--quit-buffers debug)))))
    (dolist (buffer (delete-dups buffers))
      (when (buffer-live-p buffer)
        (dolist (window (get-buffer-window-list buffer nil t))
          (with-selected-window window
            (ignore-errors (delete-window))))
        (when (buffer-live-p buffer)
          (ignore-errors (kill-buffer buffer)))))))

(define-key disasm-mode-map (kbd "q") #'disasm-quit)
(define-key disasm-hex-mode-map (kbd "q") #'disasm-quit)
(define-key disasm-outline-mode-map (kbd "q") #'disasm-quit)
(define-key disasm-debug-pane-mode-map (kbd "q") #'disasm-quit)

;; Execution-control keys are shared by the listing and the panes.
(dolist (map (list disasm-mode-map disasm-debug-pane-mode-map))
  (define-key map (kbd "<f5>") #'disasm-debug-continue)
  (define-key map (kbd "<f10>") #'disasm-debug-nexti)
  (define-key map (kbd "<f11>") #'disasm-debug-stepi)
  (define-key map (kbd "<S-f11>") #'disasm-debug-finish)
  (define-key map (kbd "<f2>") #'disasm-debug-toggle-breakpoint)
  (define-key map (kbd "f") #'disasm-debug-follow))

;; The panes can jump straight to a live address.
(define-key disasm-debug-pane-mode-map (kbd "g") #'disasm-debug-goto)

;; Editing is shared by the panes and the live hex view.
(define-key disasm-debug-pane-mode-map (kbd "e") #'disasm-debug-edit)
(define-key disasm-hex-mode-map (kbd "e") #'disasm-debug-edit)

(provide 'disasm)

(when disasm-bind-prefix
  (global-set-key (kbd "C-c d") disasm-prefix-map))

;;; disasm.el ends here
