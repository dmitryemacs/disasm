;;; disasm-debug-win.el --- Windows helpers for debugging with disasm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026

;; Author: disasm contributors
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, unix, languages
;; URL: https://github.com/dmitryemacs/disasm

;;; Commentary:

;; Windows-only support code for the `disasm' debugger.
;;
;; Interrupting a running target is the one operation the GDB/MI transport
;; cannot perform on Windows: GDB does not read its (pipe) standard input
;; while the inferior runs, so `-exec-interrupt' is never acted upon.  The
;; reliable primitive is the Win32 `DebugBreakProcess' call, which asks the
;; kernel to inject a breakpoint into the target; GDB, being attached,
;; observes it and stops.
;;
;; Emacs Lisp cannot call Win32 directly, so we keep a small, long-lived
;; PowerShell helper alive.  It compiles a tiny P/Invoke wrapper once and
;; then reads process ids from its standard input, answering `ok' or
;; `fail' for each.  The helper is started lazily on the first interrupt
;; and shut down when Emacs exits.

;;; Code:

(require 'cl-lib)
(require 'subr-x)

(defcustom disasm-debug-win-shell "powershell.exe"
  "PowerShell executable used for the Windows break helper.
Set to nil to disable the helper; interrupting will then fall back to
signalling the target with `SIGINT'."
  :type '(choice (const :tag "Auto-detect" "powershell.exe") file)
  :group 'disasm)

(defconst disasm-debug-win--script
  (concat
   "$src = @'\n"
   "using System;\n"
   "using System.Runtime.InteropServices;\n"
   "public class DisasmBreak {\n"
   "  [DllImport(\"kernel32.dll\", SetLastError=true)]\n"
   "  public static extern IntPtr OpenProcess(int access, bool inherit, int pid);\n"
   "  [DllImport(\"kernel32.dll\")]\n"
   "  public static extern bool DebugBreakProcess(IntPtr handle);\n"
   "  public static bool Break(int pid) {\n"
   "    IntPtr h = OpenProcess(0x1F0FFF, false, pid);\n"
   "    if (h == IntPtr.Zero) return false;\n"
   "    return DebugBreakProcess(h);\n"
   "  }\n"
   "}\n"
   "'@\n"
   "Add-Type -TypeDefinition $src\n"
   "[Console]::Out.WriteLine('ready')\n"
   "[Console]::Out.Flush()\n"
   "while ($true) {\n"
   "  $line = [Console]::In.ReadLine()\n"
   "  if ($null -eq $line) { break }\n"
   "  $line = $line.Trim()\n"
   "  if ($line -eq '') { continue }\n"
   "  $v = 0\n"
   "  if (-not [int]::TryParse($line, [ref]$v)) {\n"
   "    [Console]::Out.WriteLine('bad'); [Console]::Out.Flush(); continue\n"
   "  }\n"
   "  if ([DisasmBreak]::Break($v)) { [Console]::Out.WriteLine('ok') }\n"
   "  else { [Console]::Out.WriteLine('fail') }\n"
   "  [Console]::Out.Flush()\n"
   "}\n")
  "PowerShell script implementing the persistent break helper.")

(defvar disasm-debug-win--process nil
  "The persistent PowerShell helper process, or nil.")

(defvar disasm-debug-win--ready nil
  "Non-nil once the helper has announced that it is ready.")

(defvar disasm-debug-win--input ""
  "Raw output received from the helper that has not been parsed yet.")

(defvar disasm-debug-win--replies nil
  "List of complete reply lines received from the helper.")

(defun disasm-debug-win-available-p ()
  "Return non-nil when the Windows break helper can be used."
  (and (eq system-type 'windows-nt)
       disasm-debug-win-shell
       (executable-find disasm-debug-win-shell)))

(defun disasm-debug-win--filter (_process chunk)
  "Collect CHUNK from the helper, extracting the readiness banner and replies."
  (setq disasm-debug-win--input (concat disasm-debug-win--input chunk))
  (unless disasm-debug-win--ready
    (when (string-match "ready\r?\n" disasm-debug-win--input)
      (setq disasm-debug-win--ready t)
      (setq disasm-debug-win--input
            (substring disasm-debug-win--input (match-end 0)))))
  (when disasm-debug-win--ready
    (while (string-match "\\`\\([^\r\n]*\\)\r?\n" disasm-debug-win--input)
      (let ((line (match-string 1 disasm-debug-win--input)))
        (setq disasm-debug-win--input
              (substring disasm-debug-win--input (match-end 0)))
        (unless (string-empty-p line)
          (setq disasm-debug-win--replies
                (append disasm-debug-win--replies (list line))))))))

(defun disasm-debug-win--start ()
  "Start the helper process.  Return it, or nil on failure."
  (when (disasm-debug-win-available-p)
    (setq disasm-debug-win--ready nil
          disasm-debug-win--input ""
          disasm-debug-win--replies nil)
    (condition-case err
        (setq disasm-debug-win--process
              (make-process
               :name "disasm-win-break"
               :command (list disasm-debug-win-shell
                              "-NoProfile" "-NonInteractive" "-Command"
                              disasm-debug-win--script)
               :connection-type 'pipe
               :coding 'utf-8-unix
               :noquery t
               :filter #'disasm-debug-win--filter
               :sentinel (lambda (_process _event)
                           (setq disasm-debug-win--ready nil))))
      (error
       (message "disasm: cannot start the Windows break helper: %s"
                (error-message-string err))
       nil))))

(defun disasm-debug-win--ensure ()
  "Make sure the helper is running and ready.  Return it, or nil."
  (let ((process (and (process-live-p disasm-debug-win--process)
                      disasm-debug-win--process)))
    (unless (and process disasm-debug-win--ready)
      (setq process (disasm-debug-win--start)))
    (when process
      (let ((deadline (+ (float-time) 20)))
        (while (and (< (float-time) deadline)
                    (process-live-p process)
                    (not disasm-debug-win--ready))
          (accept-process-output process 0.05)))
      (and disasm-debug-win--ready process))))

(defun disasm-debug-win-break-process (pid)
  "Ask the kernel to inject a breakpoint into the process PID.
Return t when the request succeeded, the symbol `fail' when the kernel
refused it, and nil when the helper is unavailable."
  (when (and (integerp pid) (disasm-debug-win--ensure))
    (setq disasm-debug-win--replies nil)
    (process-send-string disasm-debug-win--process (format "%d\n" pid))
    (let ((deadline (+ (float-time) 5)))
      (while (and (< (float-time) deadline)
                  (process-live-p disasm-debug-win--process)
                  (null disasm-debug-win--replies))
        (accept-process-output disasm-debug-win--process 0.05)))
    (pcase (car disasm-debug-win--replies)
      ("ok" t)
      ("fail" 'fail)
      (_ nil))))

(defun disasm-debug-win-stop ()
  "Shut the helper process down, if it is running."
  (let ((process disasm-debug-win--process))
    (setq disasm-debug-win--process nil
          disasm-debug-win--ready nil
          disasm-debug-win--input ""
          disasm-debug-win--replies nil)
    (when (process-live-p process)
      (ignore-errors (process-send-eof process))
      (ignore-errors (delete-process process)))))

(add-hook 'kill-emacs-hook #'disasm-debug-win-stop)

(provide 'disasm-debug-win)
;;; disasm-debug-win.el ends here
