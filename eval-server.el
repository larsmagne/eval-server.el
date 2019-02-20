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

;; (push "~/src/eval-server.el" load-path)
;; (autoload 'start-eval-server "eval-server" nil t)

;; To test:

;; (start-eval-server "lights" 8710 '(+))
;; (eval-at "lights" "stories" 8710 '(+ 1 2))
;;
;; ~/.authinfo:
;; machine lights port 8710 password secret

;; Description of the protocol between client and server:
;;
;; The protocol is sexp-based; it's a plist that looks like this:
;;
;; (:iv "1m687rP6n8Ch7VfNu0joEw=="
;;  :cipher AES-256-CBC
;;  :message "iFfFOl/sMxLb6ExwOuxFvsnvU1L1RNp4uarw1PHSR6M=")
;;
;; :message is encrypted using the cipher named, and the :iv is the
;; usual intialisation vector (i.e., a random number used as a kind of
;; salt).
;;
;; All data is base64-encoded to help with avoiding binary data loss.
;;
;; The server should respond with the same cipher as the client
;; requested, and if it doesn't support that, an error is returned.
;; Speaking of which, if there's an error, :message will not be
;; present, but instead there will be an
;;
;; :error "iFfFOl/sMxLb6ExwOuxFvsnvU1L1RNp4uarw1PHSR6M="
;;
;; present in the response (which is encrypted the same way as the
;; message would have been).
;;
;; Additionally, if the error happened during the dispatch phase of
;; the server (i.e., when actually evalling the form the client sent
;; over), a
;;
;; :signal wrong-type-argument
;;
;; (or the like) will be present that says what Emacs Lisp type the
;; error was.

;;; Code:

(defvar eval-server--processes nil)

(defun start-eval-server (name port functions)
  "Start server NAME listening to PORT accepting FUNCTIONS.

If a server is already listening to PORT, it is deleted first.

If NAME is nil, the server expects the data to be \"encrypted\"
with the passphrase \"nil\"."
  (let ((server (assq port eval-server--processes)))
    (when server
      (delete-process (cdr server))
      (setq eval-server--processes (delq server eval-server--processes))))
  (let ((auth (car (auth-source-search :max 1 :port port :host name))))
    (unless auth
      (error "Couldn't find encryption secret in ~/.authinfo"))
    (push (cons port
		(make-network-process
		 :name name
		 :buffer (get-buffer-create " *eval-server*")
		 :family 'ipv4
		 :service port
		 :host (system-name)
		 :filter-multibyte nil
		 :filter (lambda (proc string)
			   (eval-server--filter
			    proc auth string functions))
		 :sentinel 'eval-server--sentinel
		 :server t))
	  eval-server--processes))
  (message "Server %s listening on port %s" name port))

(defun eval-at (name host port form)
  "Connect to HOST:PORT and eval FORM there.
NAME is used to find the encryption password from your password
store, which may be ~/.authinfo.  If NAME is nil, the data is
obfuscated with the passphrase \"nil\"."
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (let ((proc
	   (open-network-stream (format "eval-at-%s" host) (current-buffer)
				host port))
	  (auth (and name
		     (car (auth-source-search :max 1 :port port :host name)))))
      ;; Ignore any signals.
      (set-process-sentinel proc (lambda (&rest _)))
      (process-send-string
       proc (format "%S\n" (eval-server--encrypt-form auth form)))
      ;; Wait until we get a full response back.
      (while (and (process-live-p proc)
		  (not (search-forward "\n" nil t)))
	(accept-process-output proc 0 10))
      (delete-process proc)
      (goto-char (point-min))
      (when (plusp (buffer-size))
	(let* ((command (read (current-buffer)))
	       (response
		(eval-server--decrypt-command auth command)))
	  (if (plist-get command :error)
	      (signal (or (plist-get command :signal)
			  'error)
		      (format "%s" response))
	    response))))))

(defvar eval-server--clients nil)

(defun eval-server--filter (proc auth string functions)
  (let ((client (assq proc eval-server--clients)))
    (unless client
      (setq client (cons proc ""))
      (push client eval-server--clients))
    ;; Data may come in incomplete packets.  Don't try to parse
    ;; anything until we've gotten a newline.
    (let ((message (concat (cdr client) string)))
      (if (string-match "\n\\'" message)
	  (progn
	    (eval-server--dispatch proc auth message functions)
	    (delete-process (car client))
	    (eval-server--remove proc))
	;; Add this incomplete package to the cache.
	(setcdr client message)))))

(defun eval-server--dispatch (proc auth command functions)
  (when-let ((encrypted (condition-case err
			    (car (read-from-string command))
			  (error
			   (eval-server--reply proc auth nil err)
			   nil))))
    (let ((form (eval-server--decrypt-command auth encrypted)))
      (cond
       ((null form)
	(eval-server--reply proc auth nil "No command given from client"))
       ((not (consp form))
	(eval-server--reply
	 proc auth nil
	 (format "Invalid non-form from client: %S" form)))
       ((not (memq (car form) functions))
	(eval-server--reply
	 proc auth nil
	 (format "Non-allowed command from client: %s" (car form))))
       (t
	(let* ((success t)
	       (value
		(condition-case err
		    (apply #'funcall form)
		  (error
		   (eval-server--reply proc auth nil
				       (cdr err) (car err))
		   (setq success nil)))))
	  (when success
	    (eval-server--reply proc auth value))))))
    (process-send-eof proc)))

(defun eval-server--reply (proc auth form &optional error signal)
  (process-send-string
   proc
   (format "%S\n" (eval-server--encrypt-form auth form error signal))))

(defun eval-server--sentinel (proc message)
  (when (equal message "connection broken by remote peer\n")
    (eval-server--remove proc)))

(defun eval-server--remove (proc)
  (setq eval-server--clients (assq-delete-all proc eval-server--clients)))

(defun eval-server--pad (s length)
  "Pad string S to a modulo of LENGTH."
  (concat (make-string (- length (mod (length s) length)) ?\s)
	  s))

(defun eval-server--encrypt (message secret cipher)
  "Encrypt MESSAGE using CIPHER with SECRET.
The encrypted result and the IV are returned."
  (let ((cdata (cdr (assq cipher (gnutls-ciphers)))))
    (unless cdata
      (error "Cipher %s isn't supported" cipher))
    (gnutls-symmetric-encrypt
     cipher
     (eval-server--pad secret (plist-get cdata :cipher-keysize))
     (list 'iv-auto (plist-get cdata :cipher-ivsize))
     (eval-server--pkcs7-pad message (plist-get cdata :cipher-blocksize)))))

(defun eval-server--pkcs7-pad (string length)
  "Perform PKCS#7 padding to STRING."
  (let ((pad (- length (mod (length string) length))))
    (concat string (make-string pad pad))))

(defun eval-server--pkcs7-unpad (string)
  "Remove PKCS#7 padding from STRING."
  (substring string 0 (- (length string)
			 (aref string (1- (length string))))))

(defun eval-server--decrypt (encrypted secret cipher iv)
  (let ((cdata (cdr (assq cipher (gnutls-ciphers)))))
    (unless cdata
      (error "Cipher %s isn't supported" cipher))
    (gnutls-symmetric-decrypt
     cipher
     (eval-server--pad secret (plist-get cdata :cipher-keysize))
     iv
     encrypted)))

(defun eval-server--encrypt-form (auth form &optional error signal)
  "Encrypt FORM according to AUTH.
If ERROR, encrypt that instead."
  (let* ((message 
	  (with-temp-buffer
	    (set-buffer-multibyte nil)
	    (insert (format "%S\n" (or error form)))
	    (buffer-string)))
	 (encrypted
	  (eval-server--encrypt
	   message
	   (if auth
	       (funcall (plist-get auth :secret))
	     "nil")
	   'AES-256-CBC)))
    (nconc
     (list :cipher 'AES-256-CBC
	   :iv (base64-encode-string (cadr encrypted))
	   (if error :error :message)
	   (base64-encode-string (car encrypted)))
     (and signal
	  (list :signal signal)))))

(defun eval-server--decrypt-command (auth command)
  (when (and (plist-get command :iv)
	     (or (plist-get command :error)
		 (plist-get command :message)))
    ;; If we start supporting other ciphers in the future, we would
    ;; probably refactor the en/decryption code somewhat.
    (if (not (eq (plist-get command :cipher) 'AES-256-CBC))
	(format "Invalid cipher %s" (plist-get command :cipher))
      (let ((message
	     (car
	      (eval-server--decrypt
	       (base64-decode-string
		(or (plist-get command :error)
		    (plist-get command :message)))
	       (if auth
		   (funcall (plist-get auth :secret))
		 "nil")
	       'AES-256-CBC
	       (base64-decode-string (plist-get command :iv))))))
	(ignore-errors
	  (car (read-from-string (eval-server--pkcs7-unpad message))))))))

(provide 'eval-server)

;;; eval-server.el ends here
