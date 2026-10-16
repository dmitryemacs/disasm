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

(defvar disasm-prefix-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "f") #'disasm-file)
    (define-key map (kbd "b") #'disasm-buffer)
    (define-key map (kbd "o") #'disasm-open)
    (define-key map (kbd "r") #'disasm-open-raw)
    (define-key map (kbd "h") #'disasm-open-hex)
    (define-key map (kbd "s") #'disasm-sync-mode)
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
When TWO-PANE is non-nil, also open a synchronized hex pane.
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
        (disasm--open-two-pane session buffer)
      (pop-to-buffer buffer))
    (disasm--begin-disassembly session buffer
                               (disasm-session-entry session))
    buffer))

(defun disasm--open-two-pane (session buffer)
  "Display SESSION's BUFFER with a hex pane on the left."
  (let ((hexbuf (disasm-hex--get-buffer session)))
    (pop-to-buffer buffer)
    (let* ((disasm-win (or (get-buffer-window buffer) (selected-window)))
           (hexwin (split-window disasm-win nil 'left)))
      (set-window-buffer hexwin hexbuf)
      (select-window disasm-win))
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
  "Disassemble FILE and show a synchronized hex pane next to the listing."
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
  (disasm--open-two-pane disasm--session (current-buffer)))

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

(provide 'disasm)

(when disasm-bind-prefix
  (global-set-key (kbd "C-c d") disasm-prefix-map))

;;; disasm.el ends here
