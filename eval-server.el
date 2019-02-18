;;; eval-server.el --- a framework for doing client/server things -*- lexical-binding: t -*-
;; Copyright (C) 2019 Lars Magne Ingebrigtsen

;; Author: Lars Magne Ingebrigtsen <larsi@gnus.org>
;; Keywords: extensions, processes

;; eval-server.el is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 2, or (at your option)
;; any later version.

;; eval-server.el is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with GNU Emacs; see the file COPYING.  If not, write to the
;; Free Software Foundation, Inc., 59 Temple Place - Suite 330,
;; Boston, MA 02111-1307, USA.

;;; Commentary:

;; Put the following in your .emacs:

;; (push "~/src/eval-server" load-path)
;; (autoload 'eval-server-start "eval-server" nil t)

;;; Code:

(defvar eval-server-process nil)

(defun eval-server-start (port functions)
  (when eval-server-process
    (delete-process eval-server-process)
    (setq eval-server-process nil))
  (setq eval-server-process
	(make-network-process :name "eval-server"
			      :buffer (get-buffer-create "*eval-server*")
			      :family 'ipv4
			      :service port
			      :filter (lambda (proc string)
					(eval-server-filter
					 proc string functions))
			      :sentinel 'eval-server-sentinel
			      :server t))
  (message "Listening on port %s" port))

(defvar eval-server-clients nil)

(defun eval-server-filter (proc string functions)
  (let ((client (assq proc eval-server-clients)))
    (unless client
      (setq client (cons proc ""))
      (push client eval-server-clients))
    (let ((message (concat (cdr client) string)))
      (if (string-match "\n\\'" message)
	  (progn
	    (eval-server-dispatch proc message functions)
	    (delete-process (car client))
	    (eval-server-remove proc))
	(setcdr client message)))))

(defun eval-server-dispatch (proc message functions)
  ;; Return the last partial line.
  (if (not (string-match "\n\\'" message))
      message
    (eval-server-dispatch-1 proc message functions)))

(defun eval-server-dispatch-1 (proc command functions)
  (let ((command (ignore-errors (car (read-from-string command)))))
    (if (and command
	     (consp command)
	     (memq (car command) functions))
	(eval-server-reply proc (apply #'funcall command))
      (eval-server-reply proc (format "Invalid command %s" command)))
    (process-send-eof proc)))

(defun eval-server-reply (proc form)
  (process-send-string
   proc
   (concat
    (if (stringp form)
	form
      (format "%S" form))
    "\n")))

(defun eval-server-sentinel (proc message)
  (when (string= message "connection broken by remote peer\n")
    (eval-server-remove proc)))

(defun eval-server-remove (proc)
  (setq eval-server-clients (assq-delete-all proc eval-server-clients)))

(defun eval-at (host port form)
  (with-temp-buffer
    (let ((proc
	   (open-network-stream (format "eval-at-%s" host) (current-buffer)
				host port)))
      (set-process-sentinel proc (lambda (&rest _)))
      (process-send-string proc (format "%S\n" form))
      (while (and (process-live-p proc)
		  (not (search-forward "\n" nil t)))
	(accept-process-output proc 0 10))
      (delete-process proc)
      (goto-char (point-min))
      (and (plusp (buffer-size))
	   (read (current-buffer))))))

(provide 'eval-server)

;;; eval-server.el ends here
