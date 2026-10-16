;;; disasm-tests.el --- ERT tests for disasm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Keywords: tools

;;; Commentary:

;; Hermetic unit tests for the objdump output parsers and helpers.  These
;; do not require objdump to be installed: they operate on captured output
;; fragments.

;;; Code:

(require 'ert)
(let ((dir (file-name-directory (or load-file-name buffer-file-name))))
  (when dir
    (add-to-list 'load-path (expand-file-name ".." dir))))
(require 'disasm)

(defconst disasm-test--header-output
  (concat "hello.exe:     file format pei-x86-64\n"
          "architecture: i386:x86-64, flags 0x0000010b:\n"
          "HAS_RELOC, EXEC_P, HAS_DEBUG, D_PAGED\n"
          "start address 0x0000000140001000\n"))

(defconst disasm-test--sections-output
  (concat
   "hello.exe:     file format pei-x86-64\n"
   "\n"
   "Sections:\n"
   "Idx Name          Size      VMA               LMA               File off  Algn\n"
   "  0 .text         00001f00  0000000140001000  0000000140001000  00000600  2**4\n"
   "                  CONTENTS, ALLOC, LOAD, READONLY, CODE\n"
   "  1 .data         00001000  0000000140003000  0000000140003000  00002500  2**4\n"
   "                  CONTENTS, ALLOC, LOAD, DATA\n"))

(defconst disasm-test--disasm-output
  (concat
   "hello.exe:     file format pei-x86-64\n"
   "\n"
   "Disassembly of section .text:\n"
   "\n"
   "0000000140001000 <main>:\n"
   "   140001000:\tc3                   \tret\n"
   "   140001001:\te8 fa ff ff ff       \tcall   140001000 <main>\n"
   "   140001006:\t0f 84 34 00 00 00    \tje     140001040 <other>\n"
   "   14000100c:\tff 25 12 34 00 00    \tjmp    QWORD PTR [rip+0x3412]\n"
   "   140001012:\t48 b8 88 77 66 55 44 33 22 11 \tmovabs rax,0x1122334455667788\n"
   "   14000101c:\t90                   \tnop\n"
   "   14000101d:\t66 66 2e 0f 1f 84 00 \tdata16 cs nop WORD PTR [rax+rax*1+0x0]\n"
   "   140001024:\t00 00 00 00 \n"))

(defun disasm-test--parsed ()
  "Return the parsed disassembly fixture."
  (disasm-objdump--parse-disassembly
   disasm-test--disasm-output
   (disasm-objdump--parse-sections disasm-test--sections-output)))

(ert-deftest disasm-test-header ()
  (let ((h (disasm-objdump--parse-header disasm-test--header-output)))
    (should (equal (plist-get h :format) "pei-x86-64"))
    (should (equal (plist-get h :arch) "i386:x86-64"))
    (should (= (plist-get h :entry) #x140001000))))

(ert-deftest disasm-test-sections ()
  (let ((secs (disasm-objdump--parse-sections disasm-test--sections-output)))
    (should (= (length secs) 2))
    (let ((text (car secs)) (data (cadr secs)))
      (should (equal (disasm-section-name text) ".text"))
      (should (= (disasm-section-vma text) #x140001000))
      (should (= (disasm-section-size text) #x1f00))
      (should (= (disasm-section-fileoff text) #x600))
      (should (disasm-section-code-p text))
      (should (equal (disasm-section-name data) ".data"))
      (should-not (disasm-section-code-p data)))))

(ert-deftest disasm-test-disassembly-basics ()
  (let* ((parsed (disasm-test--parsed))
         (insns (plist-get parsed :insns))
         (labels (plist-get parsed :labels)))
    (should (= (length insns) 7))
    (should (equal labels '(("main" . #x140001000))))
    (let ((ret (aref insns 0)))
      (should (= (disasm-insn-addr ret) #x140001000))
      (should (equal (disasm-insn-mnemonic ret) "ret"))
      (should (equal (disasm-insn-operands ret) ""))
      (should (= (disasm-insn-size ret) 1))
      (should (equal (disasm-insn-label ret) "main"))
      (should (eq (disasm-insn-kind ret) 'other)))))

(ert-deftest disasm-test-disassembly-targets ()
  (let* ((insns (plist-get (disasm-test--parsed) :insns))
         (call (aref insns 1))
         (je (aref insns 2))
         (jmp (aref insns 3)))
    ;; call with a 0x-prefixed absolute target plus a symbol
    (should (eq (disasm-insn-kind call) 'call))
    (should (= (disasm-insn-target call) #x140001000))
    ;; conditional jump whose target is printed without the 0x prefix
    (should (eq (disasm-insn-kind je) 'jmp))
    (should (= (disasm-insn-target je) #x140001040))
    ;; indirect jump: no direct target
    (should (eq (disasm-insn-kind jmp) 'jmp))
    (should-not (disasm-insn-target jmp))))

(ert-deftest disasm-test-disassembly-continuation ()
  (let* ((insns (plist-get (disasm-test--parsed) :insns))
         (data16 (aref insns 6)))
    (should (equal (disasm-insn-mnemonic data16) "data16"))
    (should (equal (disasm-insn-bytes data16)
                   "66 66 2e 0f 1f 84 00 00 00 00 00"))
    (should (= (disasm-insn-size data16) 11))))

(ert-deftest disasm-test-hex-helpers ()
  (should (= (disasm--hex-to-int "0x140001000") #x140001000))
  (should (= (disasm--hex-to-int "140001000") #x140001000))
  (should (= (disasm--hex-to-int " 0X10 ") 16))
  (should (equal (disasm--format-address #x140001000 64) "0x0000000140001000"))
  (should (equal (disasm--format-address #x401000 32) "0x00401000")))

(ert-deftest disasm-test-search-helpers ()
  (let* ((i1 (disasm-insn--create :addr #x100 :line 2))
         (i2 (disasm-insn--create :addr #x110 :line 4))
         (i3 (disasm-insn--create :addr #x120 :line 6))
         (session (disasm-session--create :insns (vector i1 i2 i3))))
    (should (= (disasm-session-insn-index-for-addr session #x100) 0))
    (should (= (disasm-session-insn-index-for-addr session #x115) 1))
    (should (= (disasm-session-insn-index-for-addr session #x120) 2))
    (should (= (disasm-session-insn-index-for-addr session #x999) 2))
    (should (= (disasm-session-insn-index-exact session #x110) 1))
    (should-not (disasm-session-insn-index-exact session #x115))
    (should-not (disasm-session-insn-index-at-line session 1))
    (should (= (disasm-session-insn-index-at-line session 3) 0))
    (should (= (disasm-session-insn-index-at-line session 4) 1))
    (should (= (disasm-session-insn-index-at-line session 6) 2))))

;;; M3: hex pane and synchronization

(defconst disasm-test--code-section
  (disasm-section--create :name ".text" :vma #x1000 :size #x28 :fileoff 0
                          :flags " CONTENTS, ALLOC, LOAD, READONLY, CODE"
                          :code-p t)
  "A section with contents used by the hex tests.")

(defconst disasm-test--bss-section
  (disasm-section--create :name ".bss" :vma #x2000 :size #x10 :fileoff 0
                          :flags " ALLOC")
  "A section without file contents used by the hex tests.")

(defun disasm-test--write-bytes (bytes)
  "Write the list of BYTES to a temporary file and return its name."
  (let ((file (make-temp-file "disasm-hex-" nil ".bin"))
        (data (apply #'unibyte-string bytes)))
    (with-temp-buffer
      (set-buffer-multibyte nil)
      (insert data)
      (let ((coding-system-for-write 'no-conversion))
        (write-region (point-min) (point-max) file nil 'silent)))
    file))

(ert-deftest disasm-test-section-contents-p ()
  (should (disasm--section-has-contents-p disasm-test--code-section))
  (should-not (disasm--section-has-contents-p disasm-test--bss-section)))

(ert-deftest disasm-test-offset-vaddr-mapping ()
  (let ((session (disasm-session--create
                  :sections (list disasm-test--code-section
                                  disasm-test--bss-section))))
    (should (= (disasm--offset-to-vaddr session 0) #x1000))
    (should (= (disasm--offset-to-vaddr session #x1f) #x101f))
    (should-not (disasm--offset-to-vaddr session #x100))
    (should (= (disasm--vaddr-to-offset session #x1000) 0))
    (should (= (disasm--vaddr-to-offset session #x101f) #x1f))
    (should-not (disasm--vaddr-to-offset session #x2000))))

(ert-deftest disasm-test-insn-file-offset ()
  (let* ((session (disasm-session--create
                   :sections (list disasm-test--code-section
                                   disasm-test--bss-section)))
         (code (disasm-insn--create :addr #x1010 :size 4
                                    :section disasm-test--code-section))
         (bss (disasm-insn--create :addr #x2004 :size 4
                                   :section disasm-test--bss-section)))
    (should (= (disasm--insn-file-offset session code) #x10))
    (should-not (disasm--insn-file-offset session bss))))

(ert-deftest disasm-test-insn-at-or-after-line ()
  (let* ((i1 (disasm-insn--create :addr #x100 :line 2))
         (i2 (disasm-insn--create :addr #x110 :line 4))
         (i3 (disasm-insn--create :addr #x120 :line 6))
         (session (disasm-session--create :insns (vector i1 i2 i3))))
    (should (eq (disasm--insn-at-or-after-line session 1) i1))
    (should (eq (disasm--insn-at-or-after-line session 2) i1))
    (should (eq (disasm--insn-at-or-after-line session 3) i2))
    (should (eq (disasm--insn-at-or-after-line session 4) i2))
    (should (eq (disasm--insn-at-or-after-line session 5) i3))
    (should (eq (disasm--insn-at-or-after-line session 100) i3))
    (should-not (disasm--insn-at-or-after-line
                 (disasm-session--create :insns []) 1))))

(ert-deftest disasm-test-hex-render ()
  (let* ((file (disasm-test--write-bytes (number-sequence 0 39)))
         (session (disasm-session--create
                   :file file :bits 64
                   :sections (list disasm-test--code-section)))
         (buffer (disasm-hex--get-buffer session)))
    (with-current-buffer buffer
      ;; 40 bytes => 3 lines
      (should (= (count-lines (point-min) (point-max)) 3))
      (let ((line1 (buffer-substring-no-properties (point-min) (line-end-position 1))))
        ;; offset column
        (should (equal (substring line1 0 8) "00000000"))
        ;; vaddr column (16 hex digits)
        (should (equal (substring line1 10 26) "0000000000001000"))
        ;; first bytes and ASCII
        (should (string-match-p "00 01 02 03" line1))
        (should (string-match-p "\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.$" line1)))
      ;; a line whose bytes are printable ASCII
      (goto-char (point-min))
      (forward-line 2)
      (let ((line3 (buffer-substring-no-properties (line-beginning-position)
                                                   (line-end-position))))
        (should (equal (substring line3 0 8) "00000020"))
        (should (equal (substring line3 10 26) "0000000000001020"))
        (should (string-match-p (regexp-quote " !\"#$%&'") line3))))
    (kill-buffer buffer)
    (delete-file file)))

(ert-deftest disasm-test-hex-highlight ()
  (let* ((file (disasm-test--write-bytes (number-sequence 0 39)))
         (session (disasm-session--create
                   :file file :bits 64
                   :sections (list disasm-test--code-section)))
         (buffer (disasm-hex--get-buffer session)))
    ;; single byte at offset 0: exactly the two hex chars "00"
    (disasm--hex-highlight-bytes buffer 0 1)
    (with-current-buffer buffer
      (should (= (length disasm--hex-overlays) 1))
      (let ((ov (car disasm--hex-overlays)))
        (should (= (overlay-start ov) (+ (point-min) disasm--hex-prefix)))
        (should (= (overlay-end ov) (+ (point-min) disasm--hex-prefix 2)))))
    ;; a range crossing a line boundary produces two overlays
    (disasm--hex-highlight-bytes buffer 14 4)
    (with-current-buffer buffer
      (should (= (length disasm--hex-overlays) 2))
      (let ((starts (sort (mapcar #'overlay-start disasm--hex-overlays) #'<)))
        (should (= (car starts) (+ (point-min) disasm--hex-prefix (* 14 3))))
        (should (= (cadr starts) (+ (disasm--line-start-pos 2) disasm--hex-prefix)))))
    ;; clearing
    (disasm--hex-highlight-bytes buffer nil nil)
    (with-current-buffer buffer
      (should-not disasm--hex-overlays))
    (kill-buffer buffer)
    (delete-file file)))

;;; M4: async, cache and raw binaries

(ert-deftest disasm-test-raw-args ()
  (should-not (disasm-objdump--raw-args nil))
  (should (equal (disasm-objdump--raw-args '(:arch "i386:x86-64" :base #x1000))
                 '("-b" "binary" "-m" "i386:x86-64" "--adjust-vma=0x1000")))
  (should (equal (disasm-objdump--raw-args '(:arch "arm"))
                 '("-b" "binary" "-m" "arm"))))

(ert-deftest disasm-test-header-llvm-style ()
  (let ((h (disasm-objdump--parse-header
            (concat "x: file format coff-x86-64\n"
                    "architecture: x86_64\n"
                    "start address: 0x0000000140001000\n"))))
    (should (equal (plist-get h :format) "coff-x86-64"))
    (should (equal (plist-get h :arch) "x86_64"))
    (should (= (plist-get h :entry) #x140001000))))

(ert-deftest disasm-test-cache-basic ()
  (let ((disasm-cache-enabled t)
        (disasm-cache-max-entries 2))
    (disasm-cache-clear)
    (disasm-cache-put '("a") '(:x 1))
    (should (equal (disasm-cache-get '("a")) '(:x 1)))
    (disasm-cache-put '("b") '(:x 2))
    (disasm-cache-put '("c") '(:x 3))       ; evicts ("a")
    (should-not (disasm-cache-get '("a")))
    (should (equal (disasm-cache-get '("b")) '(:x 2)))
    (should (equal (disasm-cache-get '("c")) '(:x 3)))
    (disasm-cache-clear)
    (should-not (disasm-cache-get '("b")))))

(ert-deftest disasm-test-cache-disabled ()
  (let ((disasm-cache-enabled nil))
    (disasm-cache-clear)
    (disasm-cache-put '("a") '(:x 1))
    (should-not (disasm-cache-get '("a")))))

(ert-deftest disasm-test-cache-key-invalidation ()
  (let* ((file (disasm-test--write-bytes (number-sequence 0 9)))
         (k1 (disasm-cache-key file nil nil)))
    (should (equal k1 (disasm-cache-key file nil nil)))
    ;; options change the key
    (should-not (equal k1 (disasm-cache-key file nil t)))
    (should-not (equal k1 (disasm-cache-key file '(:arch "x") nil)))
    ;; a changed file invalidates the key (size differs)
    (with-temp-buffer
      (set-buffer-multibyte nil)
      (insert (apply #'unibyte-string (number-sequence 0 19)))
      (let ((coding-system-for-write 'no-conversion))
        (write-region (point-min) (point-max) file nil 'silent)))
    (should-not (equal k1 (disasm-cache-key file nil nil)))
    (delete-file file)))

(ert-deftest disasm-test-apply-result ()
  (let ((session (disasm-session--create :state 'loading)))
    (disasm--apply-result session '(:insns [1 2] :labels (("a" . 1))))
    (should (eq (disasm-session-state session) 'ready))
    (should (equal (disasm-session-insns session) [1 2]))
    (should (equal (disasm-session-symbols session) '(("a" . 1))))))

(ert-deftest disasm-test-render-states ()
  (let ((session (disasm-session--create :file "foo.exe" :state 'loading))
        (buffer (generate-new-buffer " *disasm-test*")))
    (with-current-buffer buffer
      (disasm-mode)
      (setq-local disasm--session session)
      (disasm-render)
      (should (string-match-p "disassembling" (buffer-string)))
      (setf (disasm-session-state session) 'error)
      (setf (disasm-session-error session) "boom")
      (disasm-render)
      (should (string-match-p "boom" (buffer-string))))
    (kill-buffer buffer)))

(defun disasm-test--face-present-p (face)
  "Return non-nil when FACE appears on some character in the current buffer."
  (let ((pos (point-min)) (found nil))
    (while (and (not found) (< pos (point-max)))
      (when (eq (get-text-property pos 'face) face)
        (setq found t))
      (setq pos (next-single-property-change pos 'face nil (point-max))))
    found))

(ert-deftest disasm-test-render-fontify-limit ()
  (let* ((session (disasm-session--create
                   :file "x.exe" :bits 64 :state 'ready
                   :sections (disasm-objdump--parse-sections
                              disasm-test--sections-output)
                   :insns (plist-get (disasm-test--parsed) :insns)))
         (buffer (generate-new-buffer " *disasm-test*")))
    (unwind-protect
        (with-current-buffer buffer
          (disasm-mode)
          (setq-local disasm--session session)
          ;; Unlimited: operands are highlighted.
          (let ((disasm-fontify-limit nil))
            (disasm-render)
            (should (disasm-test--face-present-p 'disasm-register-face)))
          ;; Tiny limit: operand highlighting is skipped.
          (let ((disasm-fontify-limit 1))
            (disasm-render)
            (should-not (disasm-test--face-present-p 'disasm-register-face))
            ;; addresses and mnemonics are still highlighted
            (should (disasm-test--face-present-p 'disasm-mnemonic-face))))
      (kill-buffer buffer))))

(provide 'disasm-tests)
;;; disasm-tests.el ends here
