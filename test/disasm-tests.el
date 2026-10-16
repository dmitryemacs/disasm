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

(defconst disasm-test--llvm-sections-output
  (concat
   "hello.exe:\tfile format coff-x86-64\n"
   "\n"
   "Sections:\n"
   "Idx Name            Size     VMA              Type\n"
   "  0                 00000000 0000000000000000 \n"
   "  1 .text           00006c28 0000000140001000 TEXT, DATA\n"
   "  2 .data           000000d0 0000000140008000 DATA\n"
   "  3 .bss            00000000 000000014000c000 BSS\n")
  "Captured `llvm-objdump -h' output (64-bit PE, variable width columns).")

(defconst disasm-test--llvm-sections32-output
  (concat
   "hello-elf32.o:\tfile format elf32-i386\n"
   "\n"
   "Sections:\n"
   "Idx Name            Size     VMA      Type\n"
   "  0                 00000000 00000000 \n"
   "  2 .text           00000097 00000000 TEXT\n"
   "  6 .eh_frame       00000078 00000000 DATA\n")
  "Captured `llvm-objdump -h' output (32-bit ELF object, narrow columns).")

(defconst disasm-test--llvm-disasm-output
  (concat
   "hello.exe:\tfile format coff-x86-64\n"
   "\n"
   "Disassembly of section .text:\n"
   "\n"
   "0000000140001000 <main>:\n"
   "140001000: c3                          \tret\n"
   "140001001: e8 fa ff ff ff              \tcall\t0x140001000 <main>\n"
   "140001006: 0f 84 34 00 00 00           \tje\t0x140001040 <other>\n"
   "14000100c: ff 25 12 34 00 00           \tjmp\tqword ptr [rip + 0x3412]\n"
   "140001012: 48 b8 88 77 66 55 44 33 22 11 \tmovabs\trax, 0x1122334455667788\n"
   "14000101c: 90                          \tnop\n")
  "Captured `llvm-objdump -d --x86-asm-syntax=intel' output.")

(defun disasm-test--parsed ()
  "Return the parsed GNU objdump disassembly fixture."
  (disasm-parse-disassembly
   disasm-test--disasm-output
   (disasm-objdump--parse-sections disasm-test--sections-output)))

(ert-deftest disasm-test-header ()
  (let ((h (disasm-parse-header disasm-test--header-output)))
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
  (let ((h (disasm-parse-header
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

;;; M5: llvm-objdump backend and PE/ELF file-offset recovery

(defun disasm-test--make-bytes (len)
  "Return a unibyte string of LEN zero bytes."
  (encode-coding-string (make-string len 0) 'binary))

(defun disasm-test--put-u16le (str off value)
  "Store VALUE at OFF in unibyte STR as a little-endian 16-bit integer."
  (aset str off (logand value #xff))
  (aset str (+ off 1) (logand (ash value -8) #xff)))

(defun disasm-test--put-u32le (str off value)
  "Store VALUE at OFF in unibyte STR as a little-endian 32-bit integer."
  (dotimes (i 4)
    (aset str (+ off i) (logand (ash value (* -8 i)) #xff))))

(defun disasm-test--put-u64le (str off value)
  "Store VALUE at OFF in unibyte STR as a little-endian 64-bit integer."
  (dotimes (i 8)
    (aset str (+ off i) (logand (ash value (* -8 i)) #xff))))

(defun disasm-test--write-binary (str)
  "Write unibyte STR to a temporary file and return its name."
  (let ((file (make-temp-file "disasm-bin-" nil ".bin"))
        (coding-system-for-write 'no-conversion))
    (write-region str nil file nil 'silent)
    file))

(defun disasm-test--make-pe ()
  "Build a minimal 64-bit PE image with a single `.text' section."
  (let* ((lfanew #x80)
         (opt-size #xF0)
         (file (disasm-test--make-bytes (+ #x188 40))))
    (aset file 0 ?M)
    (aset file 1 ?Z)
    (disasm-test--put-u32le file #x3C lfanew)          ; e_lfanew
    (aset file lfanew ?P)
    (aset file (1+ lfanew) ?E)
    (disasm-test--put-u16le file (+ lfanew 4) #x8664)  ; machine
    (disasm-test--put-u16le file (+ lfanew 6) 1)       ; number of sections
    (disasm-test--put-u16le file (+ lfanew 20) opt-size)
    (let ((opt (+ lfanew 24)))
      (disasm-test--put-u16le file opt #x20b)          ; PE32+ magic
      (disasm-test--put-u32le file (+ opt 16) #x1000)  ; address of entry point
      (disasm-test--put-u64le file (+ opt 24) #x140000000)) ; image base
    (let ((sec (+ lfanew 24 opt-size)))                ; section table
      (dotimes (i 5) (aset file (+ sec i) (aref ".text" i)))
      (disasm-test--put-u32le file (+ sec 8) #x2000)   ; virtual size
      (disasm-test--put-u32le file (+ sec 12) #x1000)  ; virtual address
      (disasm-test--put-u32le file (+ sec 16) #x2000)  ; size of raw data
      (disasm-test--put-u32le file (+ sec 20) #x400))  ; pointer to raw data
    file))

(defun disasm-test--make-elf64 ()
  "Build a minimal 64-bit little-endian ELF with a `.text' section."
  (let* ((shoff #x100)
         (shentsize 64)
         (strtab-off #x200)
         (file (disasm-test--make-bytes #x330)))
    (aset file 0 #x7f) (aset file 1 ?E) (aset file 2 ?L) (aset file 3 ?F)
    (aset file 4 2)                                     ; ELFCLASS64
    (aset file 5 1)                                     ; ELFDATA2LSB
    (aset file 6 1)                                     ; EV_CURRENT
    (disasm-test--put-u16le file #x10 2)                ; ET_EXEC
    (disasm-test--put-u16le file #x12 #x3e)             ; EM_X86_64
    (disasm-test--put-u32le file #x14 1)                ; e_version
    (disasm-test--put-u64le file #x18 #x401000)         ; e_entry
    (disasm-test--put-u64le file #x28 shoff)            ; e_shoff
    (disasm-test--put-u16le file #x34 64)               ; e_ehsize
    (disasm-test--put-u16le file #x3A shentsize)        ; e_shentsize
    (disasm-test--put-u16le file #x3C 3)                ; e_shnum
    (disasm-test--put-u16le file #x3E 2)                ; e_shstrndx
    (let ((s "\0.text\0.shstrtab\0") (i 0))
      (while (< i (length s))
        (aset file (+ strtab-off i) (aref s i))
        (setq i (1+ i))))
    (let ((b (+ shoff shentsize)))                      ; .text
      (disasm-test--put-u32le file b 1)                 ; sh_name
      (disasm-test--put-u32le file (+ b 4) 1)           ; SHT_PROGBITS
      (disasm-test--put-u64le file (+ b #x10) #x401000); sh_addr
      (disasm-test--put-u64le file (+ b #x18) #x300)    ; sh_offset
      (disasm-test--put-u64le file (+ b #x20) #x20))    ; sh_size
    (let ((b (+ shoff (* 2 shentsize))))                ; .shstrtab
      (disasm-test--put-u32le file b 7)                 ; sh_name
      (disasm-test--put-u32le file (+ b 4) 3)           ; SHT_STRTAB
      (disasm-test--put-u64le file (+ b #x18) strtab-off)
      (disasm-test--put-u64le file (+ b #x20) 17))
    file))

(ert-deftest disasm-test-llvm-sections-64 ()
  (let* ((secs (disasm-llvm--parse-sections disasm-test--llvm-sections-output))
         (text (car secs))
         (data (cadr secs))
         (bss (caddr secs)))
    (should (= (length secs) 3))
    (should (equal (disasm-section-name text) ".text"))
    (should (= (disasm-section-vma text) #x140001000))
    (should (= (disasm-section-size text) #x6c28))
    (should (disasm-section-code-p text))
    (should-not (disasm-section-fileoff text))
    (should (equal (disasm-section-name data) ".data"))
    (should-not (disasm-section-code-p data))
    (should (equal (disasm-section-name bss) ".bss"))
    (should (equal (disasm-section-flags bss) "BSS"))))

(ert-deftest disasm-test-llvm-sections-32 ()
  (let* ((secs (disasm-llvm--parse-sections disasm-test--llvm-sections32-output))
         (text (car secs)))
    (should (= (length secs) 2))
    (should (equal (disasm-section-name text) ".text"))
    (should (= (disasm-section-size text) #x97))
    (should (= (disasm-section-vma text) 0))
    (should (disasm-section-code-p text))))

(ert-deftest disasm-test-llvm-disassembly ()
  (let* ((sections (disasm-llvm--parse-sections disasm-test--llvm-sections-output))
         (parsed (disasm-parse-disassembly disasm-test--llvm-disasm-output sections))
         (insns (plist-get parsed :insns))
         (labels (plist-get parsed :labels)))
    (should (= (length insns) 6))
    (should (equal labels '(("main" . #x140001000))))
    (let ((ret (aref insns 0)))
      (should (equal (disasm-insn-mnemonic ret) "ret"))
      (should (equal (disasm-insn-operands ret) ""))
      (should (= (disasm-insn-size ret) 1))
      (should (equal (disasm-insn-bytes ret) "c3")))
    (let ((call (aref insns 1)))
      (should (eq (disasm-insn-kind call) 'call))
      (should (equal (disasm-insn-mnemonic call) "call"))
      (should (equal (disasm-insn-operands call) "0x140001000 <main>"))
      (should (= (disasm-insn-target call) #x140001000)))
    (let ((je (aref insns 2)))
      (should (eq (disasm-insn-kind je) 'jmp))
      (should (= (disasm-insn-target je) #x140001040)))
    (let ((jmp (aref insns 3)))
      (should (eq (disasm-insn-kind jmp) 'jmp))
      (should-not (disasm-insn-target jmp)))
    (let ((movabs (aref insns 4)))
      (should (equal (disasm-insn-mnemonic movabs) "movabs"))
      (should (= (disasm-insn-size movabs) 10)))))

(ert-deftest disasm-test-llvm-raw-unsupported ()
  (should-error (disasm-llvm--disasm-args "x" nil '(:arch "i386:x86-64")))
  (should-error (disasm-llvm-header "x" '(:arch "i386"))))

(ert-deftest disasm-test-llvm-args ()
  (let ((disasm-syntax 'intel) (disasm-demangle t) (disasm-llvm-objdump-extra-args nil))
    (should (equal (disasm-llvm--disasm-args "f.exe" nil nil)
                   '("-d" "--x86-asm-syntax=intel" "-C" "f.exe"))))
  (let ((disasm-syntax 'att) (disasm-demangle nil) (disasm-llvm-objdump-extra-args '("--no-show-raw-insn")))
    (should (equal (disasm-llvm--disasm-args "f.exe" t nil)
                   '("-D" "--no-show-raw-insn" "f.exe")))))

(ert-deftest disasm-test-image-pe ()
  (let* ((file (disasm-test--write-binary (disasm-test--make-pe)))
         (info (disasm-image-info file)))
    (unwind-protect
        (progn
          (should (eq (plist-get info :kind) 'pe))
          (should (= (plist-get info :bits) 64))
          (should (= (plist-get info :entry) #x140001000))
          (let* ((secs (plist-get info :sections))
                 (text (car secs)))
            (should (= (length secs) 1))
            (should (equal (disasm-section-name text) ".text"))
            (should (= (disasm-section-vma text) #x140001000))
            (should (= (disasm-section-size text) #x2000))
            (should (= (disasm-section-fileoff text) #x400))))
      (delete-file file))))

(ert-deftest disasm-test-image-elf64 ()
  (let* ((file (disasm-test--write-binary (disasm-test--make-elf64)))
         (info (disasm-image-info file)))
    (unwind-protect
        (progn
          (should (eq (plist-get info :kind) 'elf))
          (should (= (plist-get info :bits) 64))
          (should (= (plist-get info :entry) #x401000))
          (let* ((secs (plist-get info :sections))
                 (text (car secs)))
            ;; Section 0 (null) has no content and is skipped; `.text' and
            ;; `.shstrtab' both carry bytes on disk.
            (should (= (length secs) 2))
            (should (equal (disasm-section-name text) ".text"))
            (should (= (disasm-section-vma text) #x401000))
            (should (= (disasm-section-size text) #x20))
            (should (= (disasm-section-fileoff text) #x300))))
      (delete-file file))))

(ert-deftest disasm-test-image-none-for-raw ()
  (let ((file (disasm-test--write-bytes (number-sequence 0 63))))
    (unwind-protect
        (should-not (disasm-image-info file))
      (delete-file file))))

(ert-deftest disasm-test-image-fill-offsets ()
  (let* ((file (disasm-test--write-binary (disasm-test--make-pe)))
         (info (disasm-image-info file))
         (sections (list (disasm-section--create :name ".text" :vma #x140001000
                                                 :size #x6c28 :fileoff nil
                                                 :flags "TEXT, DATA" :code-p t)
                         (disasm-section--create :name ".bss" :vma #x140000000
                                                 :size 0 :fileoff nil
                                                 :flags "BSS"))))
    (unwind-protect
        (progn
          (disasm-image-fill-offsets info sections)
          (should (= (disasm-section-fileoff (car sections)) #x400))
          (should (string-match-p "CONTENTS"
                                  (disasm-section-flags (car sections))))
          (should-not (disasm-section-fileoff (cadr sections))))
      (delete-file file))))

(ert-deftest disasm-test-backend-names ()
  (should (equal (let ((disasm-backend 'objdump)) (disasm-backend-name)) "objdump"))
  (should (equal (let ((disasm-backend 'llvm-objdump)) (disasm-backend-name))
                 "llvm-objdump"))
  (should (let ((disasm-backend 'objdump)) (disasm-backend-supports-raw-p)))
  (should-not (let ((disasm-backend 'llvm-objdump))
                (disasm-backend-supports-raw-p))))

;;; M6: docked layout and sidebars

(defconst disasm-test--outline-sections
  (list (disasm-section--create :name ".text" :vma #x140001000 :size #x1000 :code-p t)
        (disasm-section--create :name ".data" :vma #x140002000 :size #x100))
  "Sections used by the sidebar tests.")

(ert-deftest disasm-test-outline-sections ()
  (let* ((session (disasm-session--create
                   :file "x.exe" :bits 64
                   :sections disasm-test--outline-sections))
         (buffer (disasm-outline--get-buffer session 'sections)))
    (unwind-protect
        (with-current-buffer buffer
          (should (eq disasm-outline-kind 'sections))
          (should (string-match-p "\\.text" (buffer-string)))
          (should (string-match-p "0x0000000140001000" (buffer-string)))
          (should (string-match-p "\\.data" (buffer-string)))
          ;; The entries are clickable and carry their address.
          (goto-char (point-min))
          (should (= (disasm-outline--address-at-point) #x140001000))
          (should (eq (get-text-property (point) 'local-map)
                      disasm-outline-entry-map))
          (should (get-text-property (point) 'mouse-face))
          ;; An addressless line yields nil.
          (goto-char (point-max))
          (should-not (disasm-outline--address-at-point)))
      (kill-buffer buffer))))

(ert-deftest disasm-test-outline-functions ()
  (let* ((session (disasm-session--create
                   :file "x.exe" :bits 64 :state 'ready
                   :sections disasm-test--outline-sections
                   :symbols '(("main" . #x140001000)
                              (".Llocal" . #x140001005)
                              (".text" . #x140001000)
                              ("helper" . #x140001100))))
         (buffer (disasm-outline--get-buffer session 'functions)))
    (unwind-protect
        (with-current-buffer buffer
          (should (eq disasm-outline-kind 'functions))
          (should (string-match-p "main" (buffer-string)))
          (should (string-match-p "helper" (buffer-string)))
          ;; Local labels and section-named symbols are filtered out.
          (should-not (string-match-p "\\.Llocal" (buffer-string)))
          (should-not (string-match-p "^\\.text" (buffer-string)))
          (goto-char (point-min))
          (should (= (disasm-outline--address-at-point) #x140001000))
          (disasm-outline-next)
          (should (= (disasm-outline--address-at-point) #x140001100)))
      (kill-buffer buffer))))

(ert-deftest disasm-test-outline-functions-loading ()
  (let* ((session (disasm-session--create
                   :file "x.exe" :bits 64 :state 'loading
                   :sections disasm-test--outline-sections))
         (buffer (disasm-outline--get-buffer session 'functions)))
    (unwind-protect
        (with-current-buffer buffer
          (should (string-match-p "disassembling" (buffer-string)))
          (should-not (disasm-outline--address-at-point)))
      (kill-buffer buffer))))

(ert-deftest disasm-test-outline-refresh ()
  (let* ((session (disasm-session--create
                   :file "x.exe" :bits 64 :state 'loading
                   :sections disasm-test--outline-sections))
         (buffer (disasm-outline--get-buffer session 'functions)))
    (unwind-protect
        (progn
          (with-current-buffer buffer
            (should (string-match-p "disassembling" (buffer-string))))
          ;; Simulate the background disassembly completing.
          (setf (disasm-session-state session) 'ready)
          (setf (disasm-session-symbols session) '(("main" . #x140001000)))
          (disasm-outline--refresh session)
          (with-current-buffer buffer
            (should (string-match-p "main" (buffer-string)))
            (should-not (string-match-p "disassembling" (buffer-string)))))
      (kill-buffer buffer))))

(ert-deftest disasm-test-render-refreshes-outline ()
  (let* ((session (disasm-session--create
                   :file "y.exe" :bits 64 :state 'loading
                   :sections disasm-test--outline-sections))
         (fnbuf (disasm-outline--get-buffer session 'functions))
         (secbuf (disasm-outline--get-buffer session 'sections))
         (buffer (generate-new-buffer " *disasm-test*")))
    (unwind-protect
        (progn
          (with-current-buffer fnbuf
            (should (string-match-p "disassembling" (buffer-string))))
          (setf (disasm-session-state session) 'ready)
          (setf (disasm-session-symbols session) '(("main" . #x140001000)))
          ;; `disasm-render' should refresh the sidebars.
          (with-current-buffer buffer
            (disasm-mode)
            (setq-local disasm--session session)
            (disasm-render))
          (with-current-buffer fnbuf
            (should (string-match-p "main" (buffer-string)))))
      (kill-buffer buffer)
      (dolist (b (list fnbuf secbuf))
        (when (buffer-live-p b) (kill-buffer b))))))

(ert-deftest disasm-test-split-fraction ()
  (save-window-excursion
    (let* ((window (selected-window))
           (total (window-width window))
           (newwin (disasm--split-fraction window 0.25 'right)))
      (should (<= (abs (- (window-width newwin) (round (* total 0.25)))) 1)))))

(ert-deftest disasm-test-docked-creates-buffers ()
  (let* ((file (disasm-test--write-bytes (number-sequence 0 39)))
         (session (disasm-session--create
                   :file file :bits 64
                   :sections (list disasm-test--code-section)))
         (dbuf (generate-new-buffer " *disasm-list*")))
    (unwind-protect
        (save-window-excursion
          (setf (disasm-session-buffer session) dbuf)
          (disasm--open-docked session dbuf)
          (should (buffer-live-p (disasm-session-sections-buffer session)))
          (should (buffer-live-p (disasm-session-functions-buffer session)))
          (should (buffer-live-p (disasm-session-hex-buffer session))))
      (kill-buffer dbuf)
      (delete-file file)
      (dolist (b (list (disasm-session-sections-buffer session)
                       (disasm-session-functions-buffer session)
                       (disasm-session-hex-buffer session)))
        (when (buffer-live-p b) (kill-buffer b))))))

(ert-deftest disasm-test-quit-key-bindings ()
  (should (eq (lookup-key disasm-mode-map (kbd "q")) #'disasm-quit))
  (should (eq (lookup-key disasm-hex-mode-map (kbd "q")) #'disasm-quit))
  (should (eq (lookup-key disasm-outline-mode-map (kbd "q")) #'disasm-quit)))

(ert-deftest disasm-test-quit-kills-buffers ()
  (let* ((file (disasm-test--write-bytes (number-sequence 0 39)))
         (session (disasm-session--create
                   :file file :bits 64
                   :sections (list disasm-test--code-section)))
         (dbuf (generate-new-buffer " *disasm-list*"))
         (hexbuf (disasm-hex--get-buffer session)))
    (unwind-protect
        (progn
          (setf (disasm-session-buffer session) dbuf)
          (disasm-outline--get-buffer session 'sections)
          (let ((fnbuf (disasm-outline--get-buffer session 'functions)))
            (with-current-buffer fnbuf
              (disasm-quit))
            (should-not (buffer-live-p fnbuf))
            (should-not (buffer-live-p dbuf))
            (should-not (buffer-live-p hexbuf))))
      (delete-file file)
      (dolist (b (list dbuf hexbuf
                       (disasm-session-sections-buffer session)
                       (disasm-session-functions-buffer session)))
        (when (buffer-live-p b) (kill-buffer b))))))

;;; Layouts: taking over the frame

(ert-deftest disasm-test-collapse-default ()
  (should (eq (default-value 'disasm-collapse-other-windows) t)))

(ert-deftest disasm-test-collapse-other-windows ()
  (save-window-excursion
    (let* ((keep (selected-window))
           (other (generate-new-buffer " *disasm-other*"))
           (extra (generate-new-buffer " *disasm-extra*")))
      (unwind-protect
          (progn
            (set-window-buffer keep other)
            (set-window-buffer (split-window keep) extra)
            (should (>= (length (window-list)) 2))
            ;; When enabled, `keep' becomes the only window.
            (let ((disasm-collapse-other-windows t))
              (disasm--collapse-other-windows keep))
            (should (= (length (window-list)) 1))
            (should (eq (window-buffer keep) other))
            ;; When disabled, the split is left alone.
            (set-window-buffer (split-window keep) extra)
            (should (>= (length (window-list)) 2))
            (let ((disasm-collapse-other-windows nil))
              (disasm--collapse-other-windows keep))
            (should (>= (length (window-list)) 2)))
        (kill-buffer other)
        (kill-buffer extra)))))

(ert-deftest disasm-test-debug-layout-collapses-windows ()
  (save-window-excursion
    (let* ((session (disasm-debug-session--create
                     :backend 'gdb-mi :state 'stopped :bits 64
                     :name "t" :pid 1))
           (foreign (generate-new-buffer " *disasm-foreign*"))
           (listing (disasm-debug--prepare-session session)))
      (unwind-protect
          (progn
            ;; An unrelated window that must be collapsed away.
            (set-window-buffer (split-window) foreign)
            (should (>= (length (window-list)) 2))
            (cl-letf (((symbol-function 'disasm-debug--set-drivers) #'ignore)
                      ((symbol-function 'disasm-sync-mode) #'ignore)
                      ((symbol-function 'disasm-sync--tick) #'ignore))
              (disasm-debug--ensure-layout session))
            (let ((buffers (mapcar #'window-buffer (window-list))))
              ;; listing + hex + registers + flags + threads + stack
              (should (= (length buffers) 6))
              (should (memq listing buffers))
              (should-not (memq foreign buffers))))
        (dolist (b (list (disasm-debug-session-registers-buffer session)
                         (disasm-debug-session-flags-buffer session)
                         (disasm-debug-session-threads-buffer session)
                         (disasm-debug-session-stack-buffer session)
                         (disasm-debug-session-hex-buffer session)
                         listing foreign))
          (when (buffer-live-p b) (kill-buffer b)))))))

(ert-deftest disasm-test-docked-layout-collapses-windows ()
  (let* ((file (disasm-test--write-bytes (number-sequence 0 39)))
         (session (disasm-session--create
                   :file file :bits 64
                   :sections (list disasm-test--code-section)))
         (dbuf (generate-new-buffer " *disasm-list*"))
         (foreign (generate-new-buffer " *disasm-foreign*")))
    (unwind-protect
        (save-window-excursion
          (setf (disasm-session-buffer session) dbuf)
          ;; An unrelated window that must be collapsed away.
          (set-window-buffer (split-window) foreign)
          (should (>= (length (window-list)) 2))
          (disasm--open-docked session dbuf)
          (let ((buffers (mapcar #'window-buffer (window-list))))
            ;; listing + sections + functions + hex, nothing else
            (should (= (length buffers) 4))
            (should (memq dbuf buffers))
            (should-not (memq foreign buffers))))
      (kill-buffer dbuf)
      (kill-buffer foreign)
      (delete-file file)
      (dolist (b (list (disasm-session-sections-buffer session)
                       (disasm-session-functions-buffer session)
                       (disasm-session-hex-buffer session)))
        (when (buffer-live-p b) (kill-buffer b))))))

(ert-deftest disasm-test-open-single-pane-collapses-windows ()
  (let* ((file (disasm-test--write-bytes (number-sequence 0 39)))
         (foreign (generate-new-buffer " *disasm-foreign*"))
         (buf nil))
    (unwind-protect
        (save-window-excursion
          (let ((session (disasm-session--create
                          :file file :bits 64 :state 'loading
                          :sections (list disasm-test--code-section))))
            (set-window-buffer (split-window) foreign)
            (should (>= (length (window-list)) 2))
            ;; `disasm--open' runs objdump; keep the test hermetic.
            (setq buf (cl-letf (((symbol-function 'disasm--build-session)
                                 (lambda (&rest _) session))
                                ((symbol-function 'disasm--begin-disassembly)
                                 #'ignore))
                       (disasm--open file)))
            (let ((buffers (mapcar #'window-buffer (window-list))))
              (should (= (length buffers) 1))
              (should (memq buf buffers))
              (should-not (memq foreign buffers)))))
      (kill-buffer foreign)
      (when (buffer-live-p buf) (kill-buffer buf))
      (delete-file file))))

(ert-deftest disasm-test-open-hex-pane-collapses-windows ()
  (let* ((file (disasm-test--write-bytes (number-sequence 0 39)))
         (session (disasm-session--create
                   :file file :bits 64 :state 'ready
                   :sections (list disasm-test--code-section)))
         (dbuf (generate-new-buffer " *disasm-list*"))
         (foreign (generate-new-buffer " *disasm-foreign*")))
    (unwind-protect
        (save-window-excursion
          (setf (disasm-session-buffer session) dbuf)
          (set-window-buffer (split-window) foreign)
          (should (>= (length (window-list)) 2))
          (cl-letf (((symbol-function 'disasm-sync-mode) #'ignore)
                    ((symbol-function 'disasm-sync--tick) #'ignore))
            (disasm--open-hex-pane session dbuf))
          (let ((buffers (mapcar #'window-buffer (window-list))))
            ;; listing + hex, nothing else
            (should (= (length buffers) 2))
            (should (memq dbuf buffers))
            (should-not (memq foreign buffers))))
      (kill-buffer dbuf)
      (kill-buffer foreign)
      (delete-file file)
      (when (buffer-live-p (disasm-session-hex-buffer session))
        (kill-buffer (disasm-session-hex-buffer session))))))

;;; GDB/MI parser

(ert-deftest disasm-test-mi-parse-done-value ()
  (let ((record (disasm-mi--parse-record ?^ "done,value=\"0x1234\"")))
    (should (eq (plist-get record :type) ?^))
    (should (equal (plist-get record :class) "done"))
    (should (equal (disasm-mi-field (plist-get record :data) "value") "0x1234"))))

(ert-deftest disasm-test-mi-parse-bare-class ()
  (let ((record (disasm-mi--parse-record ?* "stopped")))
    (should (eq (plist-get record :type) ?*))
    (should (equal (plist-get record :class) "stopped"))
    (should (null (plist-get record :data)))))

(ert-deftest disasm-test-mi-parse-nested-tuple ()
  (let* ((record (disasm-mi--parse-record
                  ?^ "done,frame={addr=\"0x401000\",func=\"main\",args=[]}"))
         (frame (disasm-mi-field (plist-get record :data) "frame")))
    (should (equal (disasm-mi-field frame "addr") "0x401000"))
    (should (equal (disasm-mi-field frame "func") "main"))
    (should (equal (disasm-mi-field frame "args") nil))))

(ert-deftest disasm-test-mi-parse-list-of-values ()
  (let* ((record (disasm-mi--parse-record ?^ "done,register-names=[\"rax\",\"rbx\"]"))
         (names (disasm-mi-field (plist-get record :data) "register-names")))
    (should (equal names '("rax" "rbx")))))

(ert-deftest disasm-test-mi-parse-list-of-results ()
  (let* ((record (disasm-mi--parse-record
                  ?^ "done,body=[bkpt={number=\"1\"},bkpt={number=\"2\"}]"))
         (body (disasm-mi-field (plist-get record :data) "body")))
    (should (= (length body) 2))
    (should (equal (disasm-mi-field (cdr (nth 0 body)) "number") "1"))
    (should (equal (disasm-mi-field (cdr (nth 1 body)) "number") "2"))))

(ert-deftest disasm-test-mi-parse-stream ()
  (let ((record (disasm-mi--parse-record ?~ "\"hello\\n\"")))
    (should (eq (plist-get record :type) ?~))
    (should (equal (plist-get record :text) "hello\n"))))

(ert-deftest disasm-test-mi-parse-string-escapes ()
  (let ((record (disasm-mi--parse-record ?^ "done,value=\"a\\\"b\\tc\"")))
    (should (equal (disasm-mi-field (plist-get record :data) "value")
                   "a\"b\tc"))))

(ert-deftest disasm-test-mi-parse-octal-escape ()
  (let ((record (disasm-mi--parse-record ?~ "\"\\101\"")))
    (should (equal (plist-get record :text) "A"))))

(ert-deftest disasm-test-mi-dispatch-correlates-token ()
  (let* ((client (disasm-mi-client--create :acc ""))
         (seen nil))
    (push (cons 7 (lambda (record) (setq seen (disasm-mi-field
                                               (plist-get record :data) "value"))))
          (disasm-mi-client-pending client))
    (disasm-mi--dispatch client "7^done,value=\"42\"")
    (should (equal seen "42"))
    (should (null (disasm-mi-client-pending client)))))

(ert-deftest disasm-test-mi-dispatch-async ()
  (let* ((client (disasm-mi-client--create :acc ""))
         (records nil))
    (setf (disasm-mi-client-on-record client)
          (lambda (record _token) (push (plist-get record :class) records)))
    (disasm-mi--dispatch client "*stopped,reason=\"breakpoint-hit\"")
    (disasm-mi--dispatch client "=thread-created,id=\"1\"")
    (should (equal records '("thread-created" "stopped")))))

;;; GDB backend parsing

(defconst disasm-test--info-registers
  (concat
   "rax            0x4ff70f2000        343447379968\n"
   "rbx            0x0                 0\n"
   "rsp            0x4ff77ff908        0x4ff77ff908\n"
   "rip            0x7ff81b611121      0x7ff81b611121 <ntdll!DbgBreakPoint+1>\n"
   "eflags         0x246               [ PF ZF IF ]\n"
   "cs             0x33                51\n"
   "xmm0           {v8_bfloat16 = {0x0}}\n"))

(ert-deftest disasm-test-gdb-parse-registers ()
  (pcase-let ((`(,registers ,flags)
               (disasm-debug-gdb--parse-registers disasm-test--info-registers)))
    (should (equal (cdr (assoc "rax" registers)) "0x4ff70f2000"))
    (should (equal (cdr (assoc "rip" registers)) "0x7ff81b611121"))
    (should (equal (cdr (assoc "cs" registers)) "0x33"))
    (should (equal flags #x246))
    (should (null (assoc "xmm0" registers)))))

(defconst disasm-test--info-files
  (concat
   "Symbols from \"C:\\path\\dbgprog.exe\".\n"
   "Local exec file:\n"
   "\t`C:\\path\\dbgprog.exe', file type pei-x86-64.\n"
   "\tEntry point: 0x7ff7c4c513f0\n"
   "\t0x00007ff7c4c51000 - 0x00007ff7c4c526d8 is .text\n"
   "\t0x00007ff7c4c5b000 - 0x00007ff7c4c5b078 is .reloc\n"
   "\t0x00007ff81b571000 - 0x00007ff81b68a312 is .text in C:\\Windows\\SYSTEM32\\ntdll.dll\n"
   "\t0x00007ff81b768000 - 0x00007ff81b768554 is .reloc in C:\\Windows\\SYSTEM32\\ntdll.dll\n"))

(ert-deftest disasm-test-gdb-parse-info-files ()
  (let* ((info (disasm-debug-gdb--parse-info-files disasm-test--info-files))
         (modules (plist-get info :modules))
         (main (cl-find-if #'disasm-debug-module-main-p modules))
         (ntdll (cl-find-if (lambda (m)
                              (string-match-p "ntdll" (disasm-debug-module-path m)))
                            modules)))
    (should (equal (plist-get info :main) "C:\\path\\dbgprog.exe"))
    (should (= (plist-get info :entry) #x7ff7c4c513f0))
    (should (= (plist-get info :bits) 64))
    (should (= (length modules) 2))
    (should (= (disasm-debug-module-from main) #x7ff7c4c51000))
    (should (= (disasm-debug-module-to main) #x7ff7c4c5b078))
    (should (= (disasm-debug-module-from ntdll) #x7ff81b571000))
    (should (= (disasm-debug-module-to ntdll) #x7ff81b768554))))

(ert-deftest disasm-test-gdb-parse-frames ()
  (let* ((record (list :type ?^ :class "done"
                       :data (list (cons "stack"
                                         (list (list (cons "level" "0")
                                                     (cons "addr" "0x401000")
                                                     (cons "func" "main"))
                                               (list (cons "level" "1")
                                                     (cons "addr" "0x401100")
                                                     (cons "func" "start")))))))
         (frames (disasm-debug-gdb--frames-from-record record)))
    (should (= (length frames) 2))
    (should (= (disasm-debug-frame-addr (nth 0 frames)) #x401000))
    (should (equal (disasm-debug-frame-func (nth 0 frames)) "main"))
    (should (= (disasm-debug-frame-level (nth 1 frames)) 1))))

;;; Threads and frames

(defun disasm-test--gdb-refresh (session &optional frames threads)
  "Run a canned `disasm-debug-gdb-refresh' round trip on SESSION.
FRAMES and THREADS are the canned \"^done\" records answered for
`-stack-list-frames' and `-thread-info'.  Return a plist with the :commands
that were sent, in order, and the number of :refreshes of the UI."
  (let ((frame-record (or frames (disasm-mi--parse-record ?^ "done")))
        (thread-record (or threads (disasm-mi--parse-record ?^ "done")))
        (commands nil)
        (refreshes 0))
    ;; the refresh chain is gated on having a client at all
    (unless (disasm-debug-session-client session)
      (setf (disasm-debug-session-client session) 'canned))
    (cl-letf (((symbol-function 'disasm-debug-gdb--console)
               (lambda (_session command callback)
                 (funcall callback
                          (if (equal command "info registers")
                              "rax            0x10\n"
                            "")
                          nil)))
              ((symbol-function 'disasm-mi-send)
               (lambda (_client command callback)
                 (push command commands)
                 (funcall callback (if (equal command "-stack-list-frames")
                                       frame-record
                                     thread-record))))
              ((symbol-function 'disasm-debug--ui-refresh)
               (lambda (_session) (setq refreshes (1+ refreshes)))))
      (disasm-debug-gdb-refresh session))
    (list :commands (nreverse commands) :refreshes refreshes)))

(ert-deftest disasm-test-gdb-parse-threads ()
  (let* ((record (disasm-mi--parse-record
                  ?^ (concat "done,threads=["
                             "{id=\"1\",target-id=\"pid 7,ThreadId 0x7\","
                             "name=\"prog\",state=\"stopped\"},"
                             "{id=\"2\",target-id=\"pid 7,ThreadId 0x8\","
                             "name=\"prog\",state=\"running\"}],"
                             "current-thread-id=\"1\"")))
         (threads (disasm-debug-gdb--threads-from-record record)))
    (should (= (length threads) 2))
    (should (equal (disasm-debug-thread-id (nth 0 threads)) "1"))
    (should (equal (disasm-debug-thread-name (nth 0 threads)) "prog"))
    (should (equal (disasm-debug-thread-target-id (nth 0 threads))
                   "pid 7,ThreadId 0x7"))
    (should (equal (disasm-debug-thread-state (nth 0 threads)) "stopped"))
    (should (equal (disasm-debug-thread-state (nth 1 threads)) "running"))
    (should (equal (disasm-mi-field (plist-get record :data) "current-thread-id")
                   "1"))))

(ert-deftest disasm-test-gdb-parse-threads-empty ()
  (should (null (disasm-debug-gdb--threads-from-record
                 (disasm-mi--parse-record ?^ "done")))))

(ert-deftest disasm-test-gdb-refresh-reads-threads ()
  (let ((session (disasm-debug-session--create :state 'stopped :bits 64))
        (result nil))
    (setq result
          (disasm-test--gdb-refresh
           session
           (disasm-mi--parse-record
            ?^ (concat "done,stack=[{level=\"0\",addr=\"0x401000\","
                       "func=\"main\"},{level=\"1\",addr=\"0x402000\","
                       "func=\"start\"}]"))
           (disasm-mi--parse-record
            ?^ (concat "done,threads=[{id=\"1\",name=\"prog\","
                       "state=\"stopped\"}],current-thread-id=\"1\""))))
    (should (equal (plist-get result :commands)
                   '("-stack-list-frames" "-thread-info")))
    (should (= (plist-get result :refreshes) 1))
    (should (equal (disasm-debug-session-registers session)
                   '(("rax" . "0x10"))))
    (should (= (length (disasm-debug-session-frames session)) 2))
    (should (= (length (disasm-debug-session-threads session)) 1))
    (should (equal (disasm-debug-session-current-thread session) "1"))
    (should (= (disasm-debug-session-pc session) #x401000))))

(ert-deftest disasm-test-gdb-refresh-pc-follows-selected-frame ()
  (let ((session (disasm-debug-session--create :state 'stopped :bits 64
                                               :current-frame 1)))
    (disasm-test--gdb-refresh
     session
     (disasm-mi--parse-record
      ?^ (concat "done,stack=[{level=\"0\",addr=\"0x401000\","
                 "func=\"main\"},{level=\"1\",addr=\"0x402000\","
                 "func=\"start\"}]")))
    ;; with frame 1 selected the listing follows that frame's address
    (should (= (disasm-debug-session-pc session) #x402000))))

(ert-deftest disasm-test-gdb-thread-select ()
  (let ((session (disasm-debug-session--create :state 'stopped))
        (command nil)
        (result nil))
    (cl-letf (((symbol-function 'disasm-mi-send)
               (lambda (_client cmd callback)
                 (setq command cmd)
                 (funcall callback (list :type ?^ :class "done")))))
      (disasm-debug-gdb-thread-select session "2"
                                      (lambda (ok) (setq result ok))))
    (should (equal command "-thread-select 2"))
    (should result)
    (should (equal (disasm-debug-session-current-thread session) "2"))
    ;; switching threads puts the debugger back in the innermost frame
    (should (= (disasm-debug-session-current-frame session) 0))))

(ert-deftest disasm-test-gdb-thread-select-failure ()
  (let ((session (disasm-debug-session--create :state 'stopped
                                               :current-thread "1"))
        (result t))
    (cl-letf (((symbol-function 'disasm-mi-send)
               (lambda (_client _cmd callback)
                 (funcall callback (list :type ?^ :class "error"
                                         :data (list (cons "msg" "no")))))))
      (disasm-debug-gdb-thread-select session "9"
                                      (lambda (ok) (setq result ok))))
    (should-not result)
    ;; a failed selection leaves the state alone
    (should (equal (disasm-debug-session-current-thread session) "1"))))

(ert-deftest disasm-test-gdb-stack-select-frame ()
  (let ((session (disasm-debug-session--create :state 'stopped))
        (command nil)
        (result nil))
    (cl-letf (((symbol-function 'disasm-mi-send)
               (lambda (_client cmd callback)
                 (setq command cmd)
                 (funcall callback (list :type ?^ :class "done")))))
      (disasm-debug-gdb-stack-select-frame session 2
                                           (lambda (ok) (setq result ok))))
    (should (equal command "-stack-select-frame 2"))
    (should result)
    (should (= (disasm-debug-session-current-frame session) 2))))

(ert-deftest disasm-test-debug-select-frame-dispatch ()
  (let ((session (disasm-debug-session--create :backend 'gdb-mi :state 'stopped))
        (command nil))
    (cl-letf (((symbol-function 'disasm-mi-send)
               (lambda (_client cmd callback)
                 (setq command cmd)
                 (funcall callback (list :type ?^ :class "done")))))
      (disasm-debug-select-frame session 3))
    (should (equal command "-stack-select-frame 3"))))

(ert-deftest disasm-test-debug-select-thread-dispatch ()
  (let ((session (disasm-debug-session--create :backend 'gdb-mi :state 'stopped))
        (command nil))
    (cl-letf (((symbol-function 'disasm-mi-send)
               (lambda (_client cmd callback)
                 (setq command cmd)
                 (funcall callback (list :type ?^ :class "done")))))
      (disasm-debug-select-thread session "4"))
    (should (equal command "-thread-select 4"))
    (should (equal (disasm-debug-session-current-thread session) "4"))))

(ert-deftest disasm-test-select-context-requires-stopped ()
  (let ((session (disasm-debug-session--create :backend 'gdb-mi :state 'running)))
    (should-error (disasm-debug-select-frame session 1) :type 'user-error)
    (should-error (disasm-debug-select-thread session "1") :type 'user-error)))

(ert-deftest disasm-test-stopped-resets-frame ()
  (let ((session (disasm-debug-session--create :state 'stopped)))
    (setf (disasm-debug-session-current-frame session) 3)
    (setf (disasm-debug-session-current-thread session) "4")
    (disasm-debug-gdb--on-record
     session
     (disasm-mi--parse-record
      ?* "stopped,reason=\"breakpoint-hit\",thread-id=\"2\",bkptno=\"1\"")
     nil)
    ;; a stop puts the debugger back in the innermost frame of that thread
    (should (= (disasm-debug-session-current-frame session) 0))
    (should (equal (disasm-debug-session-current-thread session) "2"))
    (should (eq (disasm-debug-session-state session) 'stopped))
    (should (= (disasm-debug-session-hit-breakpoint session) 1))))

(ert-deftest disasm-test-threads-pane-buffer ()
  (let ((session (disasm-debug-session--create :name "t" :pid 1 :state 'stopped)))
    (let ((buffer (disasm-debug-pane--get-buffer session 'threads)))
      (unwind-protect
          (progn
            (should (buffer-live-p buffer))
            (should (eq buffer (disasm-debug-session-threads-buffer session)))
            (with-current-buffer buffer
              (should (eq disasm-debug-pane-kind 'threads))))
        (kill-buffer buffer)))))

(ert-deftest disasm-test-render-threads ()
  (let ((session (disasm-debug-session--create
                  :state 'stopped :current-thread "2"
                  :threads (list (disasm-debug-thread--create
                                  :id "1" :name "prog" :state "stopped")
                                 (disasm-debug-thread--create
                                  :id "2" :name "prog" :state "stopped")))))
    (with-temp-buffer
      (disasm-debug-pane-mode)
      (setq-local buffer-read-only nil)
      (setq-local disasm-debug-pane-kind 'threads)
      (setq-local disasm-debug-pane-session session)
      (disasm-debug-pane--render-threads session)
      (goto-char (point-min))
      (should (re-search-forward "^> 2 " nil t))
      ;; the other thread carries no marker
      (goto-char (point-min))
      (should (re-search-forward "^  1 " nil t))
      ;; every thread line knows the thread it stands for
      (goto-char (point-min))
      (re-search-forward "^  1 " nil t)
      (should (equal (disasm-debug-pane--thread-at-point) "1"))
      (should-not (disasm-debug-pane--address-at-point)))))

(ert-deftest disasm-test-pane-goto-selects-thread ()
  (let ((session (disasm-debug-session--create
                  :state 'stopped
                  :threads (list (disasm-debug-thread--create
                                  :id "1" :name "prog" :state "stopped")
                                 (disasm-debug-thread--create
                                  :id "2" :name "prog" :state "stopped"))))
        (chosen nil))
    (cl-letf (((symbol-function 'disasm-debug-select-thread)
               (lambda (_session id) (setq chosen id))))
      (with-temp-buffer
        (disasm-debug-pane-mode)
        (setq-local buffer-read-only nil)
        (setq-local disasm-debug-pane-kind 'threads)
        (setq-local disasm-debug-pane-session session)
        (disasm-debug-pane--render-threads session)
        (goto-char (point-min))
        (forward-line 2)                ; the second thread
        (disasm-debug-pane-goto)))
    (should (equal chosen "2"))))

(ert-deftest disasm-test-pane-goto-selects-frame ()
  (let ((session (disasm-debug-session--create
                  :state 'stopped :bits 64 :current-frame 0
                  :frames (list (disasm-debug-frame--create
                                 :level 0 :addr #x401000 :func "main")
                                (disasm-debug-frame--create
                                 :level 1 :addr #x402000 :func "start"))))
        (chosen nil))
    (cl-letf (((symbol-function 'disasm-debug-select-frame)
               (lambda (_session level) (setq chosen level))))
      (with-temp-buffer
        (disasm-debug-pane-mode)
        (setq-local buffer-read-only nil)
        (setq-local disasm-debug-pane-kind 'stack)
        (setq-local disasm-debug-pane-session session)
        (disasm-debug-pane--render-stack session)
        (goto-char (point-min))
        (forward-line 2)                ; frame #1
        (disasm-debug-pane-goto)))
    (should (equal chosen 1))))

(ert-deftest disasm-test-render-stack-current-frame ()
  ;; the marker follows the selected frame, not always the innermost one
  (let ((session (disasm-debug-session--create
                  :state 'stopped :bits 64 :current-frame 1
                  :frames (list (disasm-debug-frame--create
                                 :level 0 :addr #x401000 :func "main")
                                (disasm-debug-frame--create
                                 :level 1 :addr #x402000 :func "start")))))
    (with-temp-buffer
      (disasm-debug-pane-mode)
      (setq-local buffer-read-only nil)
      (setq-local disasm-debug-pane-kind 'stack)
      (setq-local disasm-debug-pane-session session)
      (disasm-debug-pane--render-stack session)
      (goto-char (point-min))
      (should (re-search-forward "^>#1 " nil t))
      (goto-char (point-min))
      (should (re-search-forward "^ #0 " nil t)))))

(ert-deftest disasm-test-pane-next-threads ()
  (let ((session (disasm-debug-session--create
                  :state 'stopped :current-thread "1"
                  :threads (list (disasm-debug-thread--create
                                  :id "1" :name "prog" :state "stopped")
                                 (disasm-debug-thread--create
                                  :id "2" :name "prog" :state "stopped")))))
    (with-temp-buffer
      (disasm-debug-pane-mode)
      (setq-local buffer-read-only nil)
      (setq-local disasm-debug-pane-kind 'threads)
      (setq-local disasm-debug-pane-session session)
      (disasm-debug-pane--render-threads session)
      (goto-char (point-min))
      ;; thread lines are entries for n/p even though they carry no address
      (disasm-debug-pane-next)
      (should (equal (disasm-debug-pane--thread-at-point) "1"))
      (disasm-debug-pane-next)
      (should (equal (disasm-debug-pane--thread-at-point) "2")))))

;;; GDB breakpoints and launch

(ert-deftest disasm-test-gdb-breakpoint-from-insert ()
  (let* ((record (disasm-mi--parse-record
                  ?^ (concat "done,bkpt={number=\"2\",type=\"breakpoint\","
                             "disp=\"keep\",enabled=\"y\","
                             "addr=\"0x000000014000145a\",func=\"add\","
                             "line=\"3\",times=\"0\"}")))
         (bp (disasm-debug-gdb--breakpoint-from-record record)))
    (should (= (disasm-debug-breakpoint-number bp) 2))
    (should (= (disasm-debug-breakpoint-addr bp) #x14000145a))
    (should (disasm-debug-breakpoint-enabled bp))
    (should (equal (disasm-debug-breakpoint-func bp) "add"))
    (should (= (disasm-debug-breakpoint-line bp) 3))))

(ert-deftest disasm-test-gdb-breakpoint-disabled ()
  (let* ((record (disasm-mi--parse-record
                  ?^ "done,bkpt={number=\"1\",enabled=\"n\",addr=\"0x401000\"}"))
         (bp (disasm-debug-gdb--breakpoint-from-record record)))
    (should-not (disasm-debug-breakpoint-enabled bp))
    (should (= (disasm-debug-breakpoint-addr bp) #x401000))))

(ert-deftest disasm-test-gdb-breakpoint-from-record-error ()
  (let ((record (disasm-mi--parse-record ?^ "error,msg=\"No symbol\"")))
    (should (null (disasm-debug-gdb--breakpoint-from-record record)))))

(ert-deftest disasm-test-gdb-breakpoints-from-list ()
  (let* ((record (disasm-mi--parse-record
                  ?^ (concat "done,BreakpointTable={nr_rows=\"2\","
                             "body=[bkpt={number=\"1\",addr=\"0x401000\",func=\"main\"},"
                             "bkpt={number=\"2\",addr=\"0x401100\",func=\"add\"}]}")))
         (breakpoints (disasm-debug-gdb--breakpoints-from-record record)))
    (should (= (length breakpoints) 2))
    (should (= (disasm-debug-breakpoint-number (nth 0 breakpoints)) 1))
    (should (= (disasm-debug-breakpoint-addr (nth 1 breakpoints)) #x401100))
    (should (equal (disasm-debug-breakpoint-func (nth 0 breakpoints)) "main"))))

(ert-deftest disasm-test-gdb-breakpoints-from-empty-list ()
  (let* ((record (disasm-mi--parse-record
                  ?^ "done,BreakpointTable={nr_rows=\"0\",body=[]}"))
         (breakpoints (disasm-debug-gdb--breakpoints-from-record record)))
    (should (null breakpoints))))

(ert-deftest disasm-test-gdb-quote ()
  (should (equal (disasm-debug-gdb--quote "one two") "\"one two\""))
  (should (equal (disasm-debug-gdb--quote "") "\"\""))
  (should (equal (disasm-debug-gdb--quote nil) "\"\""))
  (should (equal (disasm-debug-gdb--quote "a\"b") "\"a\\\"b\""))
  (should (equal (disasm-debug-gdb--quote "C:\\x") "\"C:\\\\x\"")))

;;; Breakpoint bookkeeping

(ert-deftest disasm-test-debug-breakpoint-at ()
  (let ((session (disasm-debug-session--create
                  :breakpoints (list (disasm-debug-breakpoint--create
                                      :number 1 :addr #x401000)
                                     (disasm-debug-breakpoint--create
                                      :number 2 :addr #x402000)))))
    (should (= (disasm-debug-breakpoint-number
                (disasm-debug--breakpoint-at session #x402000))
               2))
    (should (null (disasm-debug--breakpoint-at session #x403000)))))

(ert-deftest disasm-test-debug-toggle-breakpoint-requires-stopped ()
  (let ((session (disasm-debug-session--create :state 'running)))
    (should-error (disasm-debug-toggle-breakpoint-at session #x401000)
                  :type 'user-error)))

(ert-deftest disasm-test-debug-toggle-breakpoint-clears-existing ()
  (let ((session (disasm-debug-session--create
                  :state 'stopped
                  :breakpoints (list (disasm-debug-breakpoint--create
                                      :number 7 :addr #x401000))))
        (deleted nil))
    (cl-letf (((symbol-function 'disasm-debug--break-delete)
               (lambda (_session number &optional callback)
                 (setq deleted number)
                 (when callback (funcall callback t)))))
      (disasm-debug-toggle-breakpoint-at session #x401000)
      (should (eql deleted 7))
      (should (null (disasm-debug-session-breakpoints session))))))

(ert-deftest disasm-test-debug-toggle-breakpoint-inserts ()
  (let ((session (disasm-debug-session--create :state 'stopped)))
    (cl-letf (((symbol-function 'disasm-debug--break-insert)
               (lambda (_session address callback)
                 (funcall callback (disasm-debug-breakpoint--create
                                    :number 1 :addr address :enabled t))))
              ((symbol-function 'disasm-debug--after-breakpoint-change)
               #'ignore))
      (disasm-debug-toggle-breakpoint-at session #x401000)
      (should (= (length (disasm-debug-session-breakpoints session)) 1))
      (should (= (disasm-debug-breakpoint-addr
                  (car (disasm-debug-session-breakpoints session)))
                 #x401000)))))

;;; Breakpoint pane

(ert-deftest disasm-test-debug-pane-render-breakpoints ()
  (let ((session (disasm-debug-session--create
                  :state 'stopped :bits 64 :hit-breakpoint 2
                  :breakpoints (list (disasm-debug-breakpoint--create
                                      :number 1 :addr #x401000
                                      :enabled t :func "main")
                                     (disasm-debug-breakpoint--create
                                      :number 2 :addr #x401100
                                      :enabled t :func "add")))))
    (with-temp-buffer
      (setq-local disasm-debug-pane-kind 'breakpoints)
      (disasm-debug-pane--render-breakpoints session)
      (let ((text (buffer-string)))
        (should (string-match-p "breakpoints" text))
        (should (string-match-p "main" text))
        (should (string-match-p "add" text))
        (should (string-match-p "401000" text))))))

(ert-deftest disasm-test-debug-pane-render-breakpoints-empty ()
  (let ((session (disasm-debug-session--create
                  :state 'stopped :bits 64 :breakpoints nil)))
    (with-temp-buffer
      (setq-local disasm-debug-pane-kind 'breakpoints)
      (disasm-debug-pane--render-breakpoints session)
      (should (string-match-p "breakpoints" (buffer-string))))))

;;; Windows break helper

(ert-deftest disasm-test-win-helper-script ()
  (should (string-match-p "DebugBreakProcess" disasm-debug-win--script))
  (should (string-match-p "OpenProcess" disasm-debug-win--script))
  (should (string-match-p "ready" disasm-debug-win--script)))

;;; New key bindings

(ert-deftest disasm-test-debug-breakpoint-bindings ()
  (should (eq (lookup-key disasm-prefix-map (kbd "R")) #'disasm-debug-run))
  (should (eq (lookup-key disasm-prefix-map (kbd "t"))
              #'disasm-debug-toggle-breakpoint))
  (should (eq (lookup-key disasm-prefix-map (kbd "B"))
              #'disasm-debug-breakpoints))
  (should (eq (lookup-key disasm-prefix-map (kbd "X"))
              #'disasm-debug-clear-breakpoints))
  (should (eq (lookup-key disasm-mode-map (kbd "<f2>"))
              #'disasm-debug-toggle-breakpoint))
  (should (eq (lookup-key disasm-debug-pane-mode-map (kbd "<f2>"))
              #'disasm-debug-toggle-breakpoint)))

;;; Address mapping and helpers

(ert-deftest disasm-test-debug-first-vma ()
  (let ((session (disasm-session--create
                  :file "x" :bits 64
                  :sections (list (disasm-section--create :name ".reloc" :vma #x1000 :size 0)
                                  (disasm-section--create :name ".text" :vma #x401000 :size #x100)
                                  (disasm-section--create :name ".data" :vma #x402000 :size #x100)))))
    (should (= (disasm-debug--first-vma session) #x401000))))

(ert-deftest disasm-test-debug-module-for-address ()
  (let ((modules (list (disasm-debug-module--create :path "a" :from #x1000 :to #x2000)
                       (disasm-debug-module--create :path "b" :from #x5000 :to #x6000))))
    (should (equal (disasm-debug-module-path
                    (disasm-debug-module-for-address modules #x1500)) "a"))
    (should (equal (disasm-debug-module-path
                    (disasm-debug-module-for-address modules #x5500)) "b"))
    (should (null (disasm-debug-module-for-address modules #x3000)))))

(ert-deftest disasm-test-debug-live-to-file ()
  (let ((session (disasm-debug-session--create :delta #x1000)))
    (should (= (disasm-debug--live-to-file session #x401000) #x400000))))

(ert-deftest disasm-test-debug-flags ()
  (should (disasm-debug-flag-set-p #x246 "ZF"))
  (should (disasm-debug-flag-set-p #x246 "PF"))
  (should (disasm-debug-flag-set-p #x246 "IF"))
  (should-not (disasm-debug-flag-set-p #x246 "CF"))
  (should-not (disasm-debug-flag-set-p #x246 "OF")))

(ert-deftest disasm-test-debug-state-label ()
  (should (equal (disasm-debug-session-state-label
                  (disasm-debug-session--create :state 'stopped))
                 "stopped")))

;;; Process enumeration

(ert-deftest disasm-test-proc-split-csv-line ()
  (should (equal (disasm-proc--split-csv-line
                  "\"System Idle Process\",\"0\",\"Services\",\"0\",\"8 K\"")
                 '("System Idle Process" "0" "Services" "0" "8 K")))
  (should (equal (disasm-proc--split-csv-line "\"a,b.exe\",\"12\"")
                 '("a,b.exe" "12")))
  (should (equal (disasm-proc--split-csv-line "\"he said \"\"hi\"\"\",\"1\"")
                 '("he said \"hi\"" "1"))))

;;; M9: live memory and arbitrary-address disassembly

(ert-deftest disasm-test-hex-string-to-unibyte ()
  (should (equal (disasm--hex-string-to-unibyte "48656c6c6f") "Hello"))
  (should (equal (disasm--hex-string-to-unibyte "") ""))
  ;; odd trailing digit is dropped
  (should (equal (length (disasm--hex-string-to-unibyte "486")) 1)))

(ert-deftest disasm-test-unibyte-to-int ()
  (should (= (disasm--unibyte-to-int (unibyte-string 1 0 0 0 0 0 0 0)) 1))
  (should (= (disasm--unibyte-to-int (unibyte-string #xff #xff)) #xffff))
  (should (= (disasm--unibyte-to-int (unibyte-string 0 1 0 0) 1 2) 1)))

(ert-deftest disasm-test-align-down ()
  (should (= (disasm--align-down #x1234 16) #x1230))
  (should (= (disasm--align-down #x1230 16) #x1230))
  (should (= (disasm--align-down #x10 0) #x10)))

(ert-deftest disasm-test-gdb-memory-from-record ()
  (let ((record
         (list :type ?^ :class "done"
               :data (list (cons "memory"
                                 (list (list (cons "begin" "0x1000")
                                             (cons "offset" "0x0")
                                             (cons "end" "0x1004")
                                             (cons "contents" "01020304"))))))))
    (should (equal (disasm-debug-gdb--memory-from-record record)
                   (unibyte-string 1 2 3 4))))
  ;; chunks are concatenated in order
  (let ((record
         (list :type ?^ :class "done"
               :data (list (cons "memory"
                                 (list (list (cons "contents" "0102"))
                                       (list (cons "contents" "0304"))))))))
    (should (equal (disasm-debug-gdb--memory-from-record record)
                   (unibyte-string 1 2 3 4))))
  ;; an error record yields nil
  (should-not (disasm-debug-gdb--memory-from-record
               (list :type ?^ :class "error"
                     :data (list (cons "msg" "Unable to read memory."))))))

(ert-deftest disasm-test-hex-render-live ()
  (with-temp-buffer
    (disasm-hex-mode)
    (disasm-hex--render-live #x400000 (unibyte-string 72 101 108 108 111) 64)
    (should disasm-hex--live)
    (should (= disasm-hex--base #x400000))
    (should (= disasm-hex--bits 64))
    (should (= disasm--hex-prefix 18))
    (let ((line (buffer-substring-no-properties (point-min) (line-end-position))))
      (should (equal (substring line 0 16) "0000000000400000"))
      (should (string-match-p "48 65 6c 6c 6f" line))
      (should (string-match-p "Hello$" line)))
    ;; highlight by byte index inside the window
    (setq-local disasm--hex-overlays nil)
    (disasm--hex-highlight-bytes (current-buffer) 1 2)
    (should (= (length disasm--hex-overlays) 1))
    (let ((ov (car disasm--hex-overlays)))
      (should (= (overlay-start ov) (+ (point-min) disasm--hex-prefix 3)))
      (should (= (overlay-end ov) (+ (point-min) disasm--hex-prefix 8))))))

(ert-deftest disasm-test-hex-live-header-line ()
  (with-temp-buffer
    (disasm-hex-mode)
    (disasm-hex--render-live #x400000 (unibyte-string 1 2 3 4) 64)
    (let ((header (disasm-hex--header-line)))
      (should (string-match-p "live memory" header))
      (should (string-match-p "0000000000400000" header)))))

(ert-deftest disasm-test-debug-operand-address ()
  (should (= (disasm-debug--operand-address
              "QWORD PTR [rip+0x3412]        # 140001040 <other>")
             #x140001040))
  (should (= (disasm-debug--operand-address "0x2dc5(%rip)  # 0x140004000")
             #x140004000))
  (should-not (disasm-debug--operand-address "0x1"))
  (should-not (disasm-debug--operand-address nil)))

(ert-deftest disasm-test-debug-follow-target ()
  (let* ((direct (disasm-insn--create :addr #x140001001 :mnemonic "call"
                                      :operands "140001040 <other>"
                                      :kind 'call :target #x140001040
                                      :size 5 :line 1))
         (indirect (disasm-insn--create
                    :addr #x14000100c :mnemonic "jmp"
                    :operands "QWORD PTR [rip+0x3412]        # 140001040 <other>"
                    :kind 'jmp :size 6 :line 1))
         (session (disasm-session--create :file "x" :bits 64
                                          :insns (vector direct) :state 'ready))
         (dsession (disasm-debug-session--create :delta #x100)))
    (with-temp-buffer
      (setq-local disasm--session session)
      (insert "x")
      (goto-char (point-min))
      (should (= (disasm-debug--follow-target dsession) (+ #x140001040 #x100))))
    (setf (disasm-session-insns session) (vector indirect))
    (with-temp-buffer
      (setq-local disasm--session session)
      (insert "x")
      (goto-char (point-min))
      (should (= (disasm-debug--follow-target dsession) (+ #x140001040 #x100))))
    ;; nothing to follow
    (setf (disasm-session-insns session)
          (vector (disasm-insn--create :addr #x140001000 :mnemonic "nop"
                                       :size 1 :line 1)))
    (with-temp-buffer
      (setq-local disasm--session session)
      (insert "x")
      (goto-char (point-min))
      (should-not (disasm-debug--follow-target dsession)))))

(ert-deftest disasm-test-debug-live-session ()
  "Live disassembly of bytes read from memory (requires objdump)."
  (skip-unless (ignore-errors (and (disasm-backend-program) t)))
  ;; mov eax, 1 ; ret
  (let* ((bytes (unibyte-string #xb8 1 0 0 0 #xc3))
         (session (disasm-debug-session--create :bits 64 :state 'stopped))
         (dsession (disasm-debug--live-session session bytes "i386:x86-64" #x1000)))
    (should dsession)
    (should (eq (disasm-session-state dsession) 'ready))
    (let ((insns (disasm-session-insns dsession)))
      (should (= (length insns) 2))
      (should (= (disasm-insn-addr (aref insns 0)) #x1000))
      (should (equal (disasm-insn-mnemonic (aref insns 0)) "mov"))
      (should (= (disasm-insn-addr (aref insns 1)) #x1005))
      (should (equal (disasm-insn-mnemonic (aref insns 1)) "ret")))
    (when (disasm-debug-session-live-file session)
      (delete-file (disasm-debug-session-live-file session)))))

;;; M11: register and memory editing

(ert-deftest disasm-test-unibyte-to-hex ()
  (should (equal (disasm--unibyte-to-hex (unibyte-string 0 #x10 #xff)) "0010ff"))
  (should (equal (disasm--unibyte-to-hex "") "")))

(ert-deftest disasm-test-debug-parse-value ()
  (should (= (disasm-debug--parse-value "0x10") 16))
  (should (= (disasm-debug--parse-value "0XFF") 255))
  (should (= (disasm-debug--parse-value "10") 16))
  (should (= (disasm-debug--parse-value "0d16") 16))
  (should (= (disasm-debug--parse-value " 0d16 ") 16))
  (should-error (disasm-debug--parse-value "") :type 'user-error)
  (should-error (disasm-debug--parse-value "0xZZ") :type 'user-error)
  (should-error (disasm-debug--parse-value "hello") :type 'user-error))

(ert-deftest disasm-test-debug-parse-bytes ()
  (should (equal (disasm-debug--parse-bytes "DE AD BE EF")
                 (unibyte-string #xde #xad #xbe #xef)))
  (should (equal (disasm-debug--parse-bytes "deadbeef")
                 (unibyte-string #xde #xad #xbe #xef)))
  (should (equal (disasm-debug--parse-bytes "0xDE 0xAD")
                 (unibyte-string #xde #xad)))
  (should (equal (disasm-debug--parse-bytes "\\xDE\\xAD")
                 (unibyte-string #xde #xad)))
  (should (equal (disasm-debug--parse-bytes "de:ad,be-ef")
                 (unibyte-string #xde #xad #xbe #xef)))
  (should-error (disasm-debug--parse-bytes "") :type 'user-error)
  (should-error (disasm-debug--parse-bytes "abc") :type 'user-error)
  (should-error (disasm-debug--parse-bytes "zz") :type 'user-error))

(ert-deftest disasm-test-gdb-write-register ()
  (let ((session (disasm-debug-session--create :state 'stopped))
        (command nil)
        (result nil))
    (cl-letf (((symbol-function 'disasm-mi-send)
               (lambda (_client cmd callback)
                 (setq command cmd)
                 (funcall callback (list :type ?^ :class "done")))))
      (disasm-debug-gdb-write-register session "rax" #x10
                                       (lambda (ok) (setq result ok))))
    (should (equal command "-gdb-set $rax = 0x10"))
    (should result)))

(ert-deftest disasm-test-gdb-write-register-failure ()
  (let ((session (disasm-debug-session--create :state 'stopped))
        (result t))
    (cl-letf (((symbol-function 'disasm-mi-send)
               (lambda (_client _cmd callback)
                 (funcall callback (list :type ?^ :class "error"
                                         :data (list (cons "msg" "bad")))))))
      (disasm-debug-gdb-write-register session "rax" 1
                                       (lambda (ok) (setq result ok))))
    (should-not result)))

(ert-deftest disasm-test-gdb-write-memory ()
  (let ((session (disasm-debug-session--create :state 'stopped))
        (command nil)
        (result nil))
    (cl-letf (((symbol-function 'disasm-mi-send)
               (lambda (_client cmd callback)
                 (setq command cmd)
                 (funcall callback (list :type ?^ :class "done")))))
      (disasm-debug-gdb-write-memory session #x401000
                                     (unibyte-string #xde #xad #xbe #xef)
                                     (lambda (ok) (setq result ok))))
    (should (equal command "-data-write-memory-bytes 0x401000 deadbeef"))
    (should result)))

(ert-deftest disasm-test-hex-byte-index-at-point ()
  (with-temp-buffer
    (disasm-hex-mode)
    (disasm-hex--render-live #x400000 (unibyte-string 1 2 3 4 5 6) 64)
    (should (= disasm--hex-prefix 18))
    (move-to-column 18)
    (should (= (disasm-hex--byte-index-at-point) 0))
    (move-to-column 33)
    (should (= (disasm-hex--byte-index-at-point) 5))
    ;; the printable-ASCII column maps to the same bytes
    (move-to-column 68)
    (should (= (disasm-hex--byte-index-at-point) 0))
    (move-to-column 70)
    (should (= (disasm-hex--byte-index-at-point) 2))
    ;; before the bytes there is no byte
    (move-to-column 5)
    (should-not (disasm-hex--byte-index-at-point))))

(ert-deftest disasm-test-hex-live-address-at-point ()
  (with-temp-buffer
    (disasm-hex-mode)
    (disasm-hex--render-live #x400000 (unibyte-string 1 2 3 4 5 6) 64)
    (move-to-column 18)
    (should (= (disasm-hex--live-address-at-point) #x400000))
    (move-to-column 33)
    (should (= (disasm-hex--live-address-at-point) #x400005))
    ;; a non-live pane has no live address
    (setq-local disasm-hex--live nil)
    (should-not (disasm-hex--live-address-at-point))))

(ert-deftest disasm-test-debug-pane-register-at-point ()
  (let ((session (disasm-debug-session--create
                  :state 'stopped :bits 64
                  :registers '(("rax" . "0x10") ("rip" . "0x1000")))))
    (with-temp-buffer
      (setq-local disasm-debug-pane-kind 'registers)
      (disasm-debug-pane--render-registers session)
      (goto-char (point-min))
      (forward-line 1)                  ; the "rax" line
      (should (equal (disasm-debug-pane--register-at-point) "rax"))
      (should (= (disasm-debug-pane--address-at-point) #x10))
      (forward-line 1)                  ; the "rip" line
      (should (equal (disasm-debug-pane--register-at-point) "rip")))))

(ert-deftest disasm-test-debug-edit-register-requires-stopped ()
  (let ((session (disasm-debug-session--create
                  :backend 'gdb-mi :state 'running :bits 64
                  :registers '(("rax" . "0x10")))))
    (with-temp-buffer
      (disasm-debug-pane-mode)
      (setq-local buffer-read-only nil)
      (setq-local disasm-debug-pane-kind 'registers)
      (setq-local disasm-debug-pane-session session)
      (disasm-debug-pane--render-registers session)
      (goto-char (point-min))
      (forward-line 1)
      (should-error (disasm-debug-edit-register) :type 'user-error))))

(ert-deftest disasm-test-debug-edit-register ()
  (let ((session (disasm-debug-session--create
                  :backend 'gdb-mi :state 'stopped :bits 64
                  :registers '(("rax" . "0x10"))))
        (command nil)
        (refreshed nil))
    (cl-letf (((symbol-function 'disasm-mi-send)
               (lambda (_client cmd callback)
                 (setq command cmd)
                 (funcall callback (list :type ?^ :class "done"))))
              ((symbol-function 'disasm-debug--refresh-state)
               (lambda (_session) (setq refreshed t))))
      (with-temp-buffer
        (disasm-debug-pane-mode)
        (setq-local buffer-read-only nil)
        (setq-local disasm-debug-pane-kind 'registers)
        (setq-local disasm-debug-pane-session session)
        (disasm-debug-pane--render-registers session)
        (goto-char (point-min))
        (forward-line 1)
        (cl-letf (((symbol-function 'read-string) (lambda (&rest _) "0x42")))
          (disasm-debug-edit-register))))
    (should (equal command "-gdb-set $rax = 0x42"))
    (should refreshed)))

(ert-deftest disasm-test-debug-edit-memory ()
  (let ((session (disasm-debug-session--create
                  :backend 'gdb-mi :state 'stopped :bits 64))
        (command nil))
    (cl-letf (((symbol-function 'disasm-mi-send)
               (lambda (_client cmd callback)
                 (setq command cmd)
                 (funcall callback (list :type ?^ :class "done"))))
              ((symbol-function 'disasm-debug--after-memory-write) #'ignore))
      (with-temp-buffer
        (disasm-hex-mode)
        (setq-local disasm-debug--session session)
        (disasm-hex--render-live #x400000 (unibyte-string 0 0 0 0) 64)
        (move-to-column 18)
        (cl-letf (((symbol-function 'read-string) (lambda (&rest _) "aa bb")))
          (disasm-debug-edit-memory))))
    (should (equal command "-data-write-memory-bytes 0x400000 aabb"))))

(ert-deftest disasm-test-debug-write-memory-requires-stopped ()
  (let ((session (disasm-debug-session--create :state 'running :bits 64)))
    (should-error (disasm-debug-edit-memory-at session #x400000)
                  :type 'user-error)))

(ert-deftest disasm-test-debug-edit-dispatch ()
  ;; in neither a pane nor a hex pane there is nothing to edit
  (with-temp-buffer
    (should-error (disasm-debug-edit) :type 'user-error)))

(ert-deftest disasm-test-debug-edit-bindings ()
  (should (eq (lookup-key disasm-prefix-map (kbd "e")) #'disasm-debug-edit))
  (should (eq (lookup-key disasm-prefix-map (kbd "w"))
              #'disasm-debug-write-memory))
  (should (eq (lookup-key disasm-prefix-map (kbd "E"))
              #'disasm-debug-set-register))
  (should (eq (lookup-key disasm-debug-pane-mode-map (kbd "e"))
              #'disasm-debug-edit))
  (should (eq (lookup-key disasm-hex-mode-map (kbd "e"))
              #'disasm-debug-edit)))

;;; M13: the MCP endpoint

(defun disasm-test--mcp-session (&rest args)
  "Build a stopped debug session for MCP tests, with ARGS overridden.
The session has a listing session of two instructions at 0x401000 and
0x401005 (file virtual addresses) and a load delta of #x1000, so live
addresses start at #x402000."
  (let* ((insns (vector (disasm-insn--create :addr #x401000 :bytes "55"
                                             :mnemonic "push" :operands "rbp"
                                             :size 1 :line 1)
                        (disasm-insn--create :addr #x401005 :bytes "c3"
                                             :mnemonic "ret" :operands ""
                                             :size 1 :line 1)))
         (listing (with-current-buffer (get-buffer-create " *disasm-test-listing*")
                    (setq-local disasm--session
                                (disasm-session--create :file "t.exe" :format "pei-x86-64"
                                                        :arch "i386:x86-64" :bits 64
                                                        :insns insns :state 'ready))
                    (current-buffer)))
         (defaults (list :backend 'gdb-mi :state 'stopped :bits 64
                         :arch "i386:x86-64" :pid 4242 :name "t.exe"
                         :exe "C:/t.exe" :pc #x402000 :listing listing
                         :delta #x1000
                         :registers '(("rax" . "0x10") ("rip" . "0x402000"))
                         :flags #x246))
         ;; `cl-defstruct' constructors keep the first of a repeated key,
         ;; so the caller's ARGS have to come before the defaults.
         (session (apply #'disasm-debug-session--create
                         (append args defaults))))
    ;; Register the session so that `disasm-mcp--sessions' finds it, just
    ;; as the debugger's own panes and listing buffers do.
    (with-current-buffer (get-buffer-create " *disasm-test-session*")
      (setq-local disasm-debug--session session))
    session))

(defun disasm-test--mcp-cleanup (session)
  "Drop the buffers SESSION's tests created."
  (let ((listing (disasm-debug-session-listing session)))
    (when (buffer-live-p listing)
      (kill-buffer listing)))
  (let ((holder (get-buffer " *disasm-test-session*")))
    (when (buffer-live-p holder)
      (kill-buffer holder))))

(ert-deftest disasm-test-mcp-json-encodes-lisp-values ()
  ;; keyword plists are objects, vectors are arrays, nil is false,
  ;; :json-null is null and other symbols become strings
  (should (equal (disasm-mcp--json '(:a t :b nil :c :json-null :d "x" :e [1 2]))
                 "{\"a\":true,\"b\":false,\"c\":null,\"d\":\"x\",\"e\":[1,2]}"))
  (should (equal (disasm-mcp--json (list :kind 'stopped))
                 "{\"kind\":\"stopped\"}"))
  (should (equal (disasm-mcp--json (list :empty (vector))) "{\"empty\":[]}"))
  (should (equal (disasm-mcp--json (list :nested (list :n 1)))
                 "{\"nested\":{\"n\":1}}")))

(ert-deftest disasm-test-mcp-json-parses-requests ()
  (let ((request (disasm-mcp--parse-json
                  "{\"id\":7,\"token\":\"t\",\"op\":\"read_memory\",\"args\":{\"address\":\"0x10\",\"length\":4}}")))
    (should (equal (alist-get 'id request) 7))
    (should (equal (disasm-mcp--arg-string request 'op) "read_memory"))
    (should (equal (disasm-mcp--arg (alist-get 'args request) 'address) "0x10"))
    (should (= (disasm-mcp--arg-number (alist-get 'args request) 'length) 4)))
  ;; arrays arrive as lists, null is dropped in favour of the default
  (let ((args (alist-get 'args (disasm-mcp--parse-json
                                "{\"args\":{\"include\":[\"registers\",\"flags\"],\"session\":null}}"))))
    (should (equal (disasm-mcp--arg args 'include) '("registers" "flags")))
    (should (equal (disasm-mcp--arg args 'session 'default) 'default)))
  (should-not (disasm-mcp--parse-json "not json")))

(ert-deftest disasm-test-mcp-arg-address ()
  (should (= (disasm-mcp--arg-address '((address . "0x401000")) 'address) #x401000))
  (should (= (disasm-mcp--arg-address '((address . "401000")) 'address) #x401000))
  (should (= (disasm-mcp--arg-address '((address . 4096)) 'address) 4096))
  (should-error (disasm-mcp--arg-address '() 'address) :type 'user-error)
  (should-error (disasm-mcp--arg-address '((address . "zz")) 'address) :type 'user-error))

(ert-deftest disasm-test-mcp-sessions-discovers-buffers ()
  (let* ((one (disasm-debug-session--create :pid 1 :name "one"))
         (two (disasm-debug-session--create :pid 2 :name "two"))
         (first (get-buffer-create " *disasm-test-one*"))
         (second (get-buffer-create " *disasm-test-two*")))
    (unwind-protect
        (progn
          (with-current-buffer first
            (setq-local disasm-debug--session one))
          (with-current-buffer second
            (setq-local disasm-debug--session two))
          ;; the same session seen through a second pane is not listed twice
          (with-temp-buffer
            (setq-local disasm-debug--session two)
            (let ((sessions (disasm-mcp--sessions)))
              (should (= (length sessions) 2))
              (should (memq one sessions))
              (should (memq two sessions))
              ;; the default session is one of them
              (should (memq (disasm-mcp--session nil) sessions))
              ;; and an explicit id selects the right one
              (should (eq (disasm-mcp--session '((session . "1"))) one))
              (should (eq (disasm-mcp--session '((session . "2"))) two))
              (should-error (disasm-mcp--session '((session . "99")))
                            :type 'user-error))))
      (kill-buffer first)
      (kill-buffer second))))

(ert-deftest disasm-test-mcp-session-selection ()
  ;; with no session at all the endpoint says so plainly
  (let ((disasm-debug--session nil))
    (cl-letf (((symbol-function 'disasm-mcp--sessions) (lambda () nil)))
      (should-error (disasm-mcp--session nil) :type 'user-error)))
  (should (equal (disasm-mcp--session-id
                  (disasm-debug-session--create :name "x"))
                 "x"))
  (should (equal (disasm-mcp--session-id
                  (disasm-debug-session--create :name "x" :pid 7))
                 "7")))

(ert-deftest disasm-test-mcp-session-json-shape ()
  (let ((session (disasm-test--mcp-session)))
    (unwind-protect
        (let ((json (disasm-mcp--session-json session)))
          (should (equal (plist-get json :id) "4242"))
          (should (equal (plist-get json :state) "stopped"))
          (should (equal (plist-get json :pc_hex) "0x0000000000402000"))
          (should (= (plist-get json :pc) #x402000))
          (should (equal (plist-get json :bits) 64)))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-state-op ()
  (let ((session (disasm-test--mcp-session
                  :reason "breakpoint-hit" :hit-breakpoint 3
                  :current-thread "1" :current-frame 0)))
    (unwind-protect
        (let ((result (disasm-mcp--op-state
                       (list (cons 'session "4242")))))
          (should (equal (plist-get result :state) "stopped"))
          (should (eq (plist-get result :stopped) t))
          (should (eq (plist-get result :exited) nil))
          (should (equal (plist-get result :reason) "breakpoint-hit"))
          (should (= (plist-get result :hit_breakpoint) 3))
          (should (equal (plist-get result :thread) "1"))
          (should (= (plist-get result :frame) 0))
          ;; no extra sections unless asked for
          (should-not (plist-get result :registers)))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-state-include-sections ()
  (let* ((session (disasm-test--mcp-session
                   :threads (list (disasm-debug-thread--create
                                   :id "1" :name "t.exe" :state "stopped"))
                   :frames (list (disasm-debug-frame--create
                                  :level 0 :addr #x401000 :func "main"))
                   :current-thread "1"
                   :modules (list (disasm-debug-module--create
                                   :path "C:/t.exe" :from #x400000 :to #x401000
                                   :main-p t))
                   :breakpoints (list (disasm-debug-breakpoint--create
                                       :number 1 :addr #x402000 :enabled t
                                       :func "main" :file "t.c" :line 3))))
         (include '("registers" "flags" "threads"
                    "frames" "modules" "breakpoints"))
         (result nil))
    (unwind-protect
        (progn
          (setq result (disasm-mcp--op-state
                        (list (cons 'session "4242")
                              (cons 'include include))))
          (should (= (length (plist-get result :registers)) 2))
          (should (equal (plist-get (aref (plist-get result :registers) 0) :name)
                         "rax"))
          (should (= (plist-get (aref (plist-get result :registers) 0) :int) #x10))
          (should (= (plist-get (plist-get result :flags) :eflags) #x246))
          (should (seq-contains-p (plist-get (plist-get result :flags) :set) "ZF"))
          (should-not (seq-contains-p (plist-get (plist-get result :flags) :set) "CF"))
          (should (= (length (plist-get result :threads)) 1))
          (should (eq (plist-get (aref (plist-get result :threads) 0) :current) t))
          (should (= (length (plist-get result :frames)) 1))
          ;; frame addresses are reported live, not as file addresses
          (should (equal (plist-get (aref (plist-get result :frames) 0) :address_hex)
                         "0x0000000000402000"))
          (should (= (length (plist-get result :modules)) 1))
          (should (eq (plist-get (aref (plist-get result :modules) 0) :main) t))
          (should (= (length (plist-get result :breakpoints)) 1))
          (should (= (plist-get (aref (plist-get result :breakpoints) 0) :number) 1))
          (should (eq (plist-get (aref (plist-get result :breakpoints) 0) :enabled) t)))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-state-unknown-section ()
  (let ((session (disasm-test--mcp-session)))
    (unwind-protect
        (should-error (disasm-mcp--op-state
                       (list (cons 'session "4242") (cons 'include '("nonsense"))))
                      :type 'user-error)
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-disassemble-from-file ()
  (let* ((session (disasm-test--mcp-session :pc #x402005))
         (result (disasm-mcp--op-disassemble
                  (list (cons 'session "4242") (cons 'address "0x402000")
                        (cons 'count 2)))))
    (unwind-protect
        (progn
          (should (equal (plist-get result :source) "file"))
          (should (= (plist-get result :count) 2))
          (let ((insns (plist-get result :instructions)))
            ;; the listing works in file addresses, the answer in live ones
            (should (= (plist-get (aref insns 0) :address) #x402000))
            (should (equal (plist-get (aref insns 0) :address_hex)
                           "0x0000000000402000"))
            (should (equal (plist-get (aref insns 0) :mnemonic) "push"))
            (should (= (plist-get (aref insns 1) :address) #x402005))
            ;; the program counter is marked
            (should (eq (plist-get (aref insns 1) :current) t))
            (should (equal (plist-get (aref insns 1) :marker) "=>")))
          (should (string-match-p "push[[:space:]]+rbp" (plist-get result :text))))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-disassemble-marks-breakpoints ()
  (let* ((session (disasm-test--mcp-session
                   :pc #x402000
                   :breakpoints (list (disasm-debug-breakpoint--create
                                       :number 2 :addr #x402005 :enabled t))))
         (result (disasm-mcp--op-disassemble
                  (list (cons 'session "4242") (cons 'address "0x402000")))))
    (unwind-protect
        (let ((insns (plist-get result :instructions)))
          (should (equal (plist-get (aref insns 1) :marker) "*"))
          (should (eq (plist-get (aref insns 1) :current) nil)))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-disassemble-live ()
  (let* ((session (disasm-test--mcp-session))
         (live (disasm-session--create
                :state 'ready :bits 64
                :insns (vector (disasm-insn--create :addr #x500000 :bytes "90"
                                                    :mnemonic "nop" :operands ""
                                                    :size 1 :line 1)))))
    (cl-letf (((symbol-function 'disasm-debug--read-window)
               (lambda (_session address _length)
                 (should (= address #x500000))
                 (unibyte-string #x90)))
              ((symbol-function 'disasm-debug--live-session)
               (lambda (_session _bytes _arch base)
                 (should (= base #x500000))
                 live)))
      ;; nothing is known about 0x500000, so the file listing cannot help
      (let ((result (disasm-mcp--op-disassemble
                     (list (cons 'session "4242") (cons 'address "0x500000")))))
        (should (equal (plist-get result :source) "live"))
        (should (= (plist-get (aref (plist-get result :instructions) 0) :address)
                   #x500000))))
    (disasm-test--mcp-cleanup session)))

(ert-deftest disasm-test-mcp-disassemble-live-requires-stopped ()
  (let ((session (disasm-test--mcp-session :state 'running)))
    (unwind-protect
        (should-error (disasm-mcp--op-disassemble
                       (list (cons 'session "4242") (cons 'address "0x900000")))
                      :type 'user-error)
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-read-memory ()
  (let ((session (disasm-test--mcp-session)))
    (unwind-protect
        (cl-letf (((symbol-function 'disasm-debug-read-memory)
                   (lambda (_session address length)
                     (should (= address #x402000))
                     (should (= length 4))
                     (unibyte-string #x41 #x42 #x00 #xff))))
          (let ((result (disasm-mcp--op-read-memory
                         (list (cons 'session "4242") (cons 'address "0x402000")
                               (cons 'length 4)))))
            (should (equal (plist-get result :hex) "414200ff"))
            (should (equal (plist-get result :ascii) "AB.."))
            (should (equal (plist-get result :u8) [65 66 0 255])))
          ;; the format argument picks the interpretation
          (let ((result (disasm-mcp--op-read-memory
                         (list (cons 'session "4242") (cons 'address "0x402000")
                               (cons 'length 4) (cons 'format "u16")))))
            (should (equal (plist-get result :values) [16961 65280]))))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-read-memory-requires-stopped ()
  (let ((session (disasm-test--mcp-session :state 'running)))
    (unwind-protect
        (should-error (disasm-mcp--op-read-memory
                       (list (cons 'session "4242") (cons 'address "0x402000")))
                      :type 'user-error)
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-read-memory-follows-agent ()
  (let ((session (disasm-test--mcp-session))
        (visited nil))
    (unwind-protect
        (cl-letf (((symbol-function 'disasm-debug-read-memory)
                   (lambda (&rest _) (unibyte-string 1 2)))
                  ((symbol-function 'disasm-debug--goto-address)
                   (lambda (_session address) (setq visited address))))
          (let ((disasm-mcp-follow-agent t))
            (disasm-mcp--op-read-memory
             (list (cons 'session "4242") (cons 'address "0x402000"))))
          (should (= visited #x402000))
          (setq visited nil)
          (let ((disasm-mcp-follow-agent nil))
            (disasm-mcp--op-read-memory
             (list (cons 'session "4242") (cons 'address "0x402000"))))
          (should-not visited))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-write-memory ()
  (let ((session (disasm-test--mcp-session))
        (command nil)
        (written nil))
    (unwind-protect
        (cl-letf (((symbol-function 'disasm-mi-send)
                   (lambda (_client cmd callback)
                     (setq command cmd)
                     (funcall callback (list :type ?^ :class "done"))))
                  ((symbol-function 'disasm-debug--after-memory-write)
                   (lambda (_session address) (setq written address))))
          (let ((result (disasm-mcp--op-write-memory
                         (list (cons 'session "4242") (cons 'address "0x402000")
                               (cons 'bytes "aa bb")))))
            (should (equal command "-data-write-memory-bytes 0x402000 aabb"))
            (should (= written #x402000))
            (should (= (plist-get result :written) 2))
            (should (equal (plist-get result :hex) "aabb"))))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-write-memory-requires-stopped ()
  (let ((session (disasm-test--mcp-session :state 'running)))
    (unwind-protect
        (should-error (disasm-mcp--op-write-memory
                       (list (cons 'session "4242") (cons 'address "0x402000")
                             (cons 'bytes "aa")))
                      :type 'user-error)
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-set-register ()
  (let ((session (disasm-test--mcp-session))
        (command nil)
        (refreshed nil))
    (unwind-protect
        (cl-letf (((symbol-function 'disasm-mi-send)
                   (lambda (_client cmd callback)
                     (setq command cmd)
                     (funcall callback (list :type ?^ :class "done"))))
                  ((symbol-function 'disasm-debug--refresh-state)
                   (lambda (_session) (setq refreshed t))))
          (let ((result (disasm-mcp--op-set-register
                         (list (cons 'session "4242") (cons 'name "rax")
                               (cons 'value "0x42")))))
            (should (equal command "-gdb-set $rax = 0x42"))
            (should refreshed)
            (should (= (plist-get result :value) #x42))
            (should (equal (plist-get result :value_hex) "0x42"))))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-set-register-reports-failure ()
  (let ((session (disasm-test--mcp-session)))
    (unwind-protect
        (cl-letf (((symbol-function 'disasm-mi-send)
                   (lambda (_client _cmd callback)
                     (funcall callback (list :type ?^ :class "error"
                                             :data (list (cons "msg" "bad")))))))
          (should-error (disasm-mcp--op-set-register
                         (list (cons 'session "4242") (cons 'name "rax")
                               (cons 'value "0x42")))
                        :type 'user-error))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-set-register-requires-name ()
  (let ((session (disasm-test--mcp-session)))
    (unwind-protect
        (should-error (disasm-mcp--op-set-register
                       (list (cons 'session "4242") (cons 'value "0x42")))
                      :type 'user-error)
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-breakpoint-set ()
  (let ((session (disasm-test--mcp-session))
        (command nil)
        (refreshed nil))
    (unwind-protect
        (cl-letf (((symbol-function 'disasm-mi-send)
                   (lambda (_client cmd callback)
                     (setq command cmd)
                     (funcall callback
                              (list :type ?^ :class "done"
                                    :data (list (cons "bkpt"
                                                      (list (cons "number" "3")
                                                            (cons "addr" "0x402010")
                                                           (cons "func" "main"))))))))
                  ((symbol-function 'disasm-debug--after-breakpoint-change)
                   (lambda (_session) (setq refreshed t))))
          (let ((result (disasm-mcp--op-breakpoint
                         (list (cons 'session "4242") (cons 'action "set")
                               (cons 'address "0x402010")))))
            (should (equal command "-break-insert *0x402010"))
            (should (= (plist-get result :number) 3))
            (should refreshed)
            (should (= (length (disasm-debug-session-breakpoints session)) 1))))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-breakpoint-set-is-idempotent ()
  (let* ((existing (disasm-debug-breakpoint--create :number 5 :addr #x402000
                                                    :enabled t))
         (session (disasm-test--mcp-session :breakpoints (list existing)))
         (sent nil))
    (unwind-protect
        (cl-letf (((symbol-function 'disasm-mi-send)
                   (lambda (&rest _) (setq sent t))))
          (let ((result (disasm-mcp--op-breakpoint
                         (list (cons 'session "4242") (cons 'action "set")
                               (cons 'address "0x402000")))))
            ;; an address that already has a breakpoint is not hit twice
            (should-not sent)
            (should (= (plist-get result :number) 5))
            (should (eq (plist-get result :existing) t))))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-breakpoint-set-failure ()
  (let ((session (disasm-test--mcp-session)))
    (unwind-protect
        (cl-letf (((symbol-function 'disasm-mi-send)
                   (lambda (_client _cmd callback)
                     (funcall callback (list :type ?^ :class "error"
                                             :data (list (cons "msg" "no")))))))
          (should-error (disasm-mcp--op-breakpoint
                         (list (cons 'session "4242") (cons 'action "set")
                               (cons 'address "0x402010")))
                        :type 'user-error)
          (should-not (disasm-debug-session-breakpoints session)))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-breakpoint-list-delete-clear ()
  (let* ((one (disasm-debug-breakpoint--create :number 1 :addr #x402000 :enabled t))
         (two (disasm-debug-breakpoint--create :number 2 :addr #x402005 :enabled t))
         (session (disasm-test--mcp-session :breakpoints (list one two)))
         (commands nil))
    (unwind-protect
        (cl-letf (((symbol-function 'disasm-mi-send)
                   (lambda (_client cmd callback)
                     (push cmd commands)
                     (funcall callback (list :type ?^ :class "done"))))
                  ((symbol-function 'disasm-debug--after-breakpoint-change) #'ignore))
          (let ((listed (disasm-mcp--op-breakpoint
                         (list (cons 'session "4242") (cons 'action "list")))))
            (should (= (length (plist-get listed :breakpoints)) 2)))
          (let ((deleted (disasm-mcp--op-breakpoint
                          (list (cons 'session "4242") (cons 'action "delete")
                                (cons 'number 1)))))
            (should (equal (nreverse commands) '("-break-delete 1")))
            (should (= (plist-get deleted :deleted) 1))
            (should (= (length (disasm-debug-session-breakpoints session)) 1)))
          (setq commands nil)
          (let ((cleared (disasm-mcp--op-breakpoint
                          (list (cons 'session "4242") (cons 'action "clear")))))
            (should (equal (nreverse commands) '("-break-delete 2")))
            (should (= (plist-get cleared :cleared) 1))
            (should-not (disasm-debug-session-breakpoints session))))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-breakpoint-delete-by-address ()
  (let* ((one (disasm-debug-breakpoint--create :number 4 :addr #x402000 :enabled t))
         (session (disasm-test--mcp-session :breakpoints (list one)))
         (commands nil))
    (unwind-protect
        (cl-letf (((symbol-function 'disasm-mi-send)
                   (lambda (_client cmd callback)
                     (push cmd commands)
                     (funcall callback (list :type ?^ :class "done"))))
                  ((symbol-function 'disasm-debug--after-breakpoint-change) #'ignore))
          (disasm-mcp--op-breakpoint
           (list (cons 'session "4242") (cons 'action "delete")
                 (cons 'address "0x402000")))
          (should (equal commands '("-break-delete 4")))
          (should-error (disasm-mcp--op-breakpoint
                         (list (cons 'session "4242") (cons 'action "delete")
                               (cons 'address "0x999000")))
                        :type 'user-error))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-breakpoint-requires-stopped ()
  (let ((session (disasm-test--mcp-session :state 'running)))
    (unwind-protect
        (progn
          (should-error (disasm-mcp--op-breakpoint
                         (list (cons 'session "4242") (cons 'action "set")
                               (cons 'address "0x402000")))
                        :type 'user-error)
          ;; listing them is always allowed
          (should (equal (plist-get (disasm-mcp--op-breakpoint
                                     (list (cons 'session "4242")
                                           (cons 'action "list")))
                                    :breakpoints)
                         [])))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-step-modes ()
  (let ((session (disasm-test--mcp-session))
        (commands nil))
    (unwind-protect
        (cl-letf (((symbol-function 'disasm-mi-send)
                   (lambda (_client cmd callback)
                     (push cmd commands)
                     (funcall callback (list :type ?^ :class "done")))))
          (disasm-mcp--op-step (list (cons 'session "4242") (cons 'mode "in")))
          (disasm-mcp--op-step (list (cons 'session "4242") (cons 'mode "over")))
          (disasm-mcp--op-step (list (cons 'session "4242") (cons 'mode "out")))
          ;; the default is a single step
          (disasm-mcp--op-step (list (cons 'session "4242")))
          (should (equal (nreverse commands)
                         '("-exec-step-instruction" "-exec-next-instruction"
                           "-exec-finish" "-exec-step-instruction"))))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-step-unknown-mode ()
  (let ((session (disasm-test--mcp-session)))
    (unwind-protect
        (should-error (disasm-mcp--op-step
                       (list (cons 'session "4242") (cons 'mode "sideways")))
                      :type 'user-error)
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-continue-requires-stopped ()
  (let ((session (disasm-test--mcp-session :state 'running)))
    (unwind-protect
        (should-error (disasm-mcp--op-continue (list (cons 'session "4242")))
                      :type 'user-error)
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-continue-sends-exec-continue ()
  (let ((session (disasm-test--mcp-session))
        (command nil))
    (unwind-protect
        (cl-letf (((symbol-function 'disasm-mi-send)
                   (lambda (_client cmd callback)
                     (setq command cmd)
                     (funcall callback (list :type ?^ :class "running")))))
          (disasm-mcp--op-continue (list (cons 'session "4242")))
          (should (equal command "-exec-continue")))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-interrupt-when-running ()
  (let ((session (disasm-test--mcp-session :state 'running :pid 4242)))
    (unwind-protect
        (cl-letf (((symbol-function 'disasm-debug-gdb--interrupt-windows) #'ignore))
          (let ((result (disasm-mcp--op-interrupt (list (cons 'session "4242")))))
            (should (equal (plist-get result :state) "running"))))
      (disasm-test--mcp-cleanup session)))
  ;; interrupting a stopped target just says so
  (let ((session (disasm-test--mcp-session)))
    (unwind-protect
        (let ((result (disasm-mcp--op-interrupt (list (cons 'session "4242")))))
          (should (plist-get result :note)))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-goto-moves-the-listing ()
  (let ((session (disasm-test--mcp-session))
        (visited nil))
    (unwind-protect
        (cl-letf (((symbol-function 'disasm-debug--goto-address)
                   (lambda (_session address) (setq visited address))))
          (let ((result (disasm-mcp--op-goto
                         (list (cons 'session "4242") (cons 'address "0x402005")))))
            (should (= visited #x402005))
            (should (= (plist-get result :address) #x402005))))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-select-thread-and-frame ()
  (let ((session (disasm-test--mcp-session))
        (commands nil))
    (unwind-protect
        (cl-letf (((symbol-function 'disasm-mi-send)
                   (lambda (_client cmd callback)
                     (push cmd commands)
                     (funcall callback (list :type ?^ :class "done"))))
                  ((symbol-function 'disasm-debug-gdb-refresh) #'ignore))
          (disasm-mcp--op-select-thread
           (list (cons 'session "4242") (cons 'id "2")))
          (disasm-mcp--op-select-frame
           (list (cons 'session "4242") (cons 'level 1)))
          (should (equal (nreverse commands)
                         '("-thread-select 2" "-stack-select-frame 1")))
          (should (equal (disasm-debug-session-current-thread session) "2"))
          (should (= (disasm-debug-session-current-frame session) 1)))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-select-thread-requires-stopped ()
  (let ((session (disasm-test--mcp-session :state 'running)))
    (unwind-protect
        (should-error (disasm-mcp--op-select-thread
                       (list (cons 'session "4242") (cons 'id "2")))
                      :type 'user-error)
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-dispatch-table ()
  (should (plist-get (disasm-mcp--op-ping nil) :pong))
  (should (equal (plist-get (disasm-mcp--op-hello nil) :protocol)
                 disasm-mcp-protocol))
  (should-error (disasm-mcp--dispatch "no_such_op" nil) :type 'user-error)
  ;; every name in the table is reachable
  (dolist (entry disasm-mcp--operations)
    (should (functionp (cdr entry)))))

;;; M13: the agent log

(ert-deftest disasm-test-mcp-log-records-calls ()
  (let ((disasm-mcp--log-entries nil)
        (disasm-mcp--log-buffer nil))
    (unwind-protect
        (progn
          (disasm-mcp--log-call "state" '((session . "7")) '(:state "stopped")
                                t 0.5 "7" #x401000)
          (disasm-mcp--log-call "step" nil '(:error "nope") nil 0.1 nil nil)
          (with-current-buffer (disasm-mcp--log-buffer)
            (should (= (length disasm-mcp--log-entries) 2))
            (goto-char (point-min))
            (should (equal (get-text-property (point) 'disasm-mcp-session) "7"))
            (should (= (get-text-property (point) 'disasm-mcp-address) #x401000))
            (should (equal (plist-get (get-text-property (point) 'disasm-mcp-entry) :op)
                           "state"))
            ;; the detail line is hidden until TAB is pressed
            (forward-line 1)
            (should (eq (get-text-property (point) 'invisible)
                        'disasm-mcp-log-detail))
            (should (member 'disasm-mcp-log-detail buffer-invisibility-spec))
            (disasm-mcp-log-toggle-details)
            (should-not (member 'disasm-mcp-log-detail buffer-invisibility-spec))
            (disasm-mcp-log-toggle-details)
            (should (member 'disasm-mcp-log-detail buffer-invisibility-spec))
            ;; the failing call is rendered as an error
            (goto-char (point-max))
            (forward-line -2)
            (should (equal (plist-get (get-text-property (point) 'disasm-mcp-entry) :op)
                           "step"))))
      (when (buffer-live-p disasm-mcp--log-buffer)
        (kill-buffer disasm-mcp--log-buffer)))))

(ert-deftest disasm-test-mcp-log-trims-its-length ()
  (let ((disasm-mcp--log-entries nil)
        (disasm-mcp--log-buffer nil)
        (disasm-mcp-log-limit 3))
    (unwind-protect
        (progn
          (dotimes (i 5)
            (disasm-mcp--log-call (format "op%d" i) nil nil t 0 nil nil))
          (should (= (length disasm-mcp--log-entries) 3))
          (with-current-buffer (disasm-mcp--log-buffer)
            ;; three rows and nothing older left
            (let ((rows 0))
              (save-excursion
                (goto-char (point-min))
                (while (not (eobp))
                  (when (get-text-property (point) 'disasm-mcp-log-row)
                    (setq rows (1+ rows)))
                  (forward-line 1)))
              (should (= rows 3)))
            (goto-char (point-min))
            (should (equal (plist-get (get-text-property (point) 'disasm-mcp-entry) :op)
                           "op2"))))
      (when (buffer-live-p disasm-mcp--log-buffer)
        (kill-buffer disasm-mcp--log-buffer)))))

(ert-deftest disasm-test-mcp-log-records-events ()
  (let ((disasm-mcp--log-entries nil)
        (disasm-mcp--log-buffer nil)
        (session (disasm-test--mcp-session)))
    (unwind-protect
        (progn
          (disasm-mcp--on-event session
                                (list :kind 'stopped :reason "breakpoint-hit"
                                      :breakpoint 2 :thread "1"))
          (let ((entry (car disasm-mcp--log-entries)))
            (should (eq (plist-get entry :ok) :event))
            (should (equal (plist-get entry :kind) "stopped"))
            (should (string-match-p "reason=breakpoint-hit" (plist-get entry :summary)))
            (should (string-match-p "bkpt=2" (plist-get entry :summary)))
            (should (equal (plist-get entry :session) "4242")))
          (disasm-mcp--on-event session (list :kind 'exited :status "exited normally"))
          (should (= (length disasm-mcp--log-entries) 2)))
      (disasm-test--mcp-cleanup session)
      (when (buffer-live-p disasm-mcp--log-buffer)
        (kill-buffer disasm-mcp--log-buffer)))))

(ert-deftest disasm-test-mcp-log-goto-needs-an-address ()
  (let ((disasm-mcp--log-entries nil)
        (disasm-mcp--log-buffer nil)
        (visited nil))
    (unwind-protect
        (progn
          (disasm-mcp--log-call "goto" nil (list :address #x401000) t 0 "7" #x401000)
          (with-current-buffer (disasm-mcp--log-buffer)
            (goto-char (point-min))
            (cl-letf (((symbol-function 'disasm-mcp--session-by-id)
                       (lambda (_id) 'fake-session))
                      ((symbol-function 'disasm-debug--goto-address)
                       (lambda (_session address) (setq visited address))))
              (disasm-mcp-log-goto)
              (should (= visited #x401000)))
            ;; an entry without an address refuses politely
            (forward-line 2)
            (should-error (disasm-mcp-log-goto) :type 'user-error)))
      (when (buffer-live-p disasm-mcp--log-buffer)
        (kill-buffer disasm-mcp--log-buffer)))))

(ert-deftest disasm-test-mcp-log-mode-is-special ()
  (with-current-buffer (get-buffer-create "*disasm-agent-test*")
    (disasm-mcp-log-mode)
    (should (derived-mode-p 'special-mode))
    (should buffer-read-only)
    (should (eq (lookup-key (current-local-map) (kbd "RET")) #'disasm-mcp-log-goto))
    (should (eq (lookup-key (current-local-map) (kbd "TAB"))
                #'disasm-mcp-log-toggle-details))
    (should (eq (lookup-key (current-local-map) (kbd "c")) #'disasm-mcp-log-clear))
    (kill-buffer (current-buffer))))

(ert-deftest disasm-test-mcp-lighter ()
  (let ((disasm-mcp--server-process nil)
        (disasm-mcp--clients nil)
        (disasm-mcp--busy nil)
        (disasm-mcp--last-op nil))
    (should (equal (disasm-mcp--lighter) " mcp:off"))
    (setq disasm-mcp--server-process 'fake)
    (cl-letf (((symbol-function 'process-live-p) (lambda (_p) t)))
      (should (equal (disasm-mcp--lighter) " mcp"))
      (setq disasm-mcp--clients (list 'a))
      (should (equal (disasm-mcp--lighter) " mcp:1"))
      (setq disasm-mcp--busy t disasm-mcp--last-op "step")
      (should (equal (disasm-mcp--lighter) " mcp:step")))))

(ert-deftest disasm-test-mcp-log-key-binding ()
  (should (eq (lookup-key disasm-prefix-map (kbd "L")) #'disasm-mcp-log)))

;;; M13: the listener protocol

(defun disasm-test--mcp-request (line &optional timeout)
  "Serve LINE through the endpoint and return the parsed answer.
The listener must already be running; see `disasm-test--with-listener'."
  (let* ((client (make-network-process
                  :name "disasm-test-client" :host "127.0.0.1"
                  :service disasm-mcp--port :family 'ipv4 :coding 'utf-8-unix
                  :noquery t))
         (answer nil)
         (acc "")
         (deadline (+ (float-time) (or timeout 5))))
    (set-process-filter client (lambda (_proc chunk) (setq acc (concat acc chunk))))
    (unwind-protect
        (progn
          (accept-process-output nil 0.05)
          (process-send-string client (concat line "\n"))
          (while (and (null answer) (< (float-time) deadline))
            (accept-process-output nil 0.05)
            (when (string-match "\n" acc)
              (setq answer (disasm-mcp--parse-json (substring acc 0 (match-beginning 0)))))))
      (ignore-errors (delete-process client)))
    answer))

(defmacro disasm-test--with-listener (&rest body)
  "Run BODY with the MCP listener up on an ephemeral port.
`disasm-mcp--token' holds the token to use and `disasm-mcp--port' the
port it bound."
  (declare (indent 0))
  `(let ((disasm-mcp-port t)
         (disasm-mcp-token-file (make-temp-file "disasm-mcp-token-"))
         (disasm-mcp--log-entries nil)
         (disasm-mcp--log-buffer nil)
         (disasm-mcp--clients nil)
         (disasm-mcp--queue nil)
         (disasm-mcp--busy nil))
     (unwind-protect
         (progn
           (disasm-mcp-start)
           ,@body)
       (disasm-mcp-stop)
       (when (buffer-live-p disasm-mcp--log-buffer)
         (kill-buffer disasm-mcp--log-buffer)))))

(ert-deftest disasm-test-mcp-listener-ping ()
  (disasm-test--with-listener
    (should (process-live-p disasm-mcp--server-process))
    (should (integerp disasm-mcp--port))
    (let* ((token disasm-mcp--token)
           (answer (disasm-test--mcp-request
                    (disasm-mcp--json (list :id 1 :token token :op "ping"
                                            :args (list))))))
      (should (eq (alist-get 'ok answer) t))
      (should (eq (alist-get 'pong (alist-get 'result answer)) t)))))

(ert-deftest disasm-test-mcp-listener-requires-the-token ()
  (disasm-test--with-listener
    (let ((answer (disasm-test--mcp-request
                   (disasm-mcp--json (list :id 2 :token "wrong" :op "sessions"
                                           :args (list))))))
      (should (eq (alist-get 'ok answer) :false))
      (should (equal (alist-get 'kind answer) "auth")))))

(ert-deftest disasm-test-mcp-listener-reports-bad-json ()
  (disasm-test--with-listener
    (let ((answer (disasm-test--mcp-request "{not json")))
      (should (eq (alist-get 'ok answer) :false))
      (should (equal (alist-get 'kind answer) "protocol")))))

(ert-deftest disasm-test-mcp-listener-rejects-unknown-ops ()
  (disasm-test--with-listener
    (let ((answer (disasm-test--mcp-request
                   (disasm-mcp--json (list :id 3 :token disasm-mcp--token
                                           :op "take_over_the_world"
                                           :args (list))))))
      (should (eq (alist-get 'ok answer) :false))
      (should (equal (alist-get 'kind answer) "user-error"))
      (should (string-match-p "Unknown operation" (alist-get 'error answer))))))

(ert-deftest disasm-test-mcp-listener-lists-live-sessions ()
  (let ((session (disasm-test--mcp-session)))
    (unwind-protect
        (with-temp-buffer
          (setq-local disasm-debug--session session)
          (disasm-test--with-listener
            (let* ((answer (disasm-test--mcp-request
                            (disasm-mcp--json (list :id 4 :token disasm-mcp--token
                                                    :op "sessions" :args (list)))))
                   (sessions (alist-get 'sessions (alist-get 'result answer))))
              (should (= (length sessions) 1))
              (should (equal (alist-get 'id (nth 0 sessions)) "4242"))
              (should (equal (alist-get 'state (nth 0 sessions)) "stopped")))))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-listener-disassembles-over-the-wire ()
  (let ((session (disasm-test--mcp-session)))
    (unwind-protect
        (with-temp-buffer
          (setq-local disasm-debug--session session)
          (disasm-test--with-listener
            (let* ((answer (disasm-test--mcp-request
                            (disasm-mcp--json
                             (list :id 5 :token disasm-mcp--token :op "disassemble"
                                   :args (list :address "0x402000" :count 2)))))
                   (result (alist-get 'result answer)))
              (should (eq (alist-get 'ok answer) t))
              (should (equal (alist-get 'source result) "file"))
              (should (= (length (alist-get 'instructions result)) 2))
              ;; the result survives the JSON round trip intact
              (should (equal (alist-get 'mnemonic
                                        (nth 1 (alist-get 'instructions result)))
                             "ret")))))
      (disasm-test--mcp-cleanup session))))

(ert-deftest disasm-test-mcp-listener-serves-several-requests-in-order ()
  (let ((session (disasm-test--mcp-session)))
    (unwind-protect
        (with-temp-buffer
          (setq-local disasm-debug--session session)
          (disasm-test--with-listener
            (let ((client (make-network-process
                           :name "disasm-test-pipeline" :host "127.0.0.1"
                           :service disasm-mcp--port :family 'ipv4
                           :coding 'utf-8-unix :noquery t))
                  (acc "")
                  (answers nil))
              (set-process-filter
               client (lambda (_proc chunk) (setq acc (concat acc chunk))))
              (unwind-protect
                  (progn
                    (accept-process-output nil 0.05)
                    (dotimes (i 3)
                      (process-send-string
                       client
                       (concat (disasm-mcp--json
                                (list :id (+ 10 i) :token disasm-mcp--token
                                      :op "state" :args (list))) "\n")))
                    (let ((deadline (+ (float-time) 5)))
                      (while (and (< (length answers) 3) (< (float-time) deadline))
                        (accept-process-output nil 0.05)
                        (while (string-match "\n" acc)
                          (let ((line (substring acc 0 (match-beginning 0))))
                            (setq acc (substring acc (match-end 0)))
                            (push (disasm-mcp--parse-json line) answers)))))
                    (setq answers (nreverse answers))
                    (should (= (length answers) 3))
                    (should (equal (mapcar (lambda (a) (alist-get 'id a)) answers)
                                   '(10 11 12)))
                    (should (equal (alist-get 'state (alist-get 'result (nth 0 answers)))
                                   "stopped")))
                (ignore-errors (delete-process client))))))
      (disasm-test--mcp-cleanup session))))

;;; M13: the event hook

(ert-deftest disasm-test-debug-event-hook-fires-while-stopping ()
  (let* ((session (disasm-test--mcp-session :state 'running))
         (events nil))
    (cl-letf (((symbol-function 'disasm-debug-gdb-refresh) #'ignore)
              ((symbol-function 'disasm-debug--ui-refresh) #'ignore))
      (let ((disasm-debug-event-hook
             (list (lambda (_session event) (push event events)))))
        (disasm-debug-gdb--on-record
         session
         (list :type ?* :class "stopped"
               :data (list (cons "reason" "breakpoint-hit")
                           (cons "bkptno" "2")
                           (cons "thread-id" "1")))
         nil)
        (should (= (length events) 1))
        (should (eq (plist-get (car events) :kind) 'stopped))
        (should (equal (plist-get (car events) :reason) "breakpoint-hit"))
        (should (= (plist-get (car events) :breakpoint) 2))
        (should (equal (plist-get (car events) :thread) "1"))
        (should (eq (disasm-debug-session-state session) 'stopped))
        (should (= (disasm-debug-session-hit-breakpoint session) 2))))
    (disasm-test--mcp-cleanup session)))

(ert-deftest disasm-test-debug-event-hook-fires-while-running ()
  (let* ((session (disasm-test--mcp-session :state 'stopped))
         (events nil))
    (cl-letf (((symbol-function 'disasm-debug--ui-refresh) #'ignore))
      (let ((disasm-debug-event-hook
             (list (lambda (_session event) (push event events)))))
        (disasm-debug-gdb--on-record
         session (list :type ?* :class "running"
                       :data (list (cons "thread-id" "1")))
         nil)
        (should (eq (plist-get (car events) :kind) 'running))
        (should (eq (disasm-debug-session-state session) 'running))))
    (disasm-test--mcp-cleanup session)))

(ert-deftest disasm-test-debug-event-hook-fires-on-thread-group ()
  (let* ((session (disasm-debug-session--create :state 'connecting :bits 64))
         (events nil))
    (let ((disasm-debug-event-hook
           (list (lambda (_session event) (push event events)))))
      (disasm-debug-gdb--on-record
       session
       (list :type ?= :class "thread-group-started"
             :data (list (cons "pid" "4242")))
       nil)
      (should (eq (plist-get (car events) :kind) 'started))
      (should (= (plist-get (car events) :pid) 4242))
      (should (= (disasm-debug-session-pid session) 4242)))))

(ert-deftest disasm-test-debug-event-hook-fires-on-exit ()
  (let* ((session (disasm-debug-session--create :state 'running :name "t.exe"))
         (events nil))
    (cl-letf (((symbol-function 'disasm-debug-pane--refresh) #'ignore))
      (let ((disasm-debug-event-hook
             (list (lambda (_session event) (push event events)))))
        (disasm-debug--on-exit session "exited normally")
        (should (eq (plist-get (car events) :kind) 'exited))
        (should (equal (plist-get (car events) :status) "exited normally"))
        (should (eq (disasm-debug-session-state session) 'exited))))))

(provide 'disasm-tests)
;;; disasm-tests.el ends here
