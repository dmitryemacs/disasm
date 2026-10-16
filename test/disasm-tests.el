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

(provide 'disasm-tests)
;;; disasm-tests.el ends here
