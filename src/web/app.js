"use strict";

(function () {
  var form = document.getElementById("form");
  var dropzone = document.getElementById("dropzone");
  var fileInput = document.getElementById("file");
  var selection = document.getElementById("selection");
  var password = document.getElementById("password");
  var confirmPassword = document.getElementById("confirm");
  var submit = document.getElementById("submit");
  var progressWrap = document.getElementById("progress-wrap");
  var progressBar = document.getElementById("progress-bar");
  var progressLabel = document.getElementById("progress-label");
  var status = document.getElementById("status");
  var result = document.getElementById("result");
  var downloadEnc = document.getElementById("download-enc");
  var downloadKey = document.getElementById("download-key");

  var MIN_PASSWORD = 12;
  var selectedFile = null;
  var objectUrls = [];
  // Refined from /api/config; the fallback matches the server default
  var maxUploadBytes = 64 * 1024 * 1024;

  var configRequest = new XMLHttpRequest();
  configRequest.open("GET", "/api/config", true);
  configRequest.addEventListener("load", function () {
    if (configRequest.status !== 200) {
      return;
    }
    try {
      var parsed = JSON.parse(configRequest.responseText);
      if (parsed && parsed.max_upload_bytes > 0) {
        maxUploadBytes = parsed.max_upload_bytes;
        if (parsed.min_password_length > 0) {
          MIN_PASSWORD = parsed.min_password_length;
        }
        if (selectedFile) {
          selectFile(selectedFile);
        }
      }
    } catch (ignored) {
      // Keep the fallback limit
    }
  });
  configRequest.send();

  function setStatus(message, kind) {
    status.textContent = message;
    status.className = "status" + (kind ? " " + kind : "");
    status.hidden = !message;
  }

  function humanSize(bytes) {
    var units = ["B", "KiB", "MiB", "GiB"];
    var value = bytes;
    var unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit++;
    }
    return (unit === 0 ? value : value.toFixed(1)) + " " + units[unit];
  }

  function releaseUrls() {
    objectUrls.forEach(URL.revokeObjectURL);
    objectUrls = [];
  }

  function offerDownload(anchor, blob, filename) {
    var url = URL.createObjectURL(blob);
    objectUrls.push(url);
    anchor.href = url;
    anchor.download = filename;
    anchor.textContent = "Download " + filename;
  }

  function tooLargeMessage(file) {
    return (
      "That file is " + humanSize(file.size) + ", above the " + humanSize(maxUploadBytes) +
      " server limit. Raise ENCRYPT_WEB_MAX_UPLOAD_MB, or encrypt it with the CLI instead."
    );
  }

  function selectFile(file) {
    selectedFile = file;
    if (!file) {
      selection.hidden = true;
      setStatus("");
      return;
    }

    selection.textContent = file.name + " (" + humanSize(file.size) + ")";
    selection.hidden = false;

    // Catching this here matters: the server's limit fires mid-upload, and
    // browsers surface that as a bare network error instead of the 413
    if (file.size > maxUploadBytes) {
      setStatus(tooLargeMessage(file), "error");
    } else {
      setStatus("");
    }
  }

  dropzone.addEventListener("click", function () {
    fileInput.click();
  });

  dropzone.addEventListener("keydown", function (event) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      fileInput.click();
    }
  });

  fileInput.addEventListener("change", function () {
    selectFile(fileInput.files.length ? fileInput.files[0] : null);
  });

  ["dragenter", "dragover"].forEach(function (name) {
    dropzone.addEventListener(name, function (event) {
      event.preventDefault();
      dropzone.classList.add("dragging");
    });
  });

  ["dragleave", "dragend", "drop"].forEach(function (name) {
    dropzone.addEventListener(name, function () {
      dropzone.classList.remove("dragging");
    });
  });

  dropzone.addEventListener("drop", function (event) {
    event.preventDefault();
    var files = event.dataTransfer && event.dataTransfer.files;
    if (files && files.length) {
      selectFile(files[0]);
    }
  });

  // Dropping anywhere else must not make the browser navigate away from the page
  window.addEventListener("dragover", function (event) {
    event.preventDefault();
  });
  window.addEventListener("drop", function (event) {
    event.preventDefault();
  });

  function filenameFromDisposition(header, fallback) {
    if (!header) {
      return fallback;
    }
    var match = /filename="([^"]+)"/.exec(header);
    return match ? match[1] : fallback;
  }

  function finish(enabled) {
    submit.disabled = !enabled;
    progressWrap.hidden = enabled;
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();

    if (!selectedFile) {
      setStatus("Choose a file first.", "error");
      return;
    }
    if (selectedFile.size > maxUploadBytes) {
      setStatus(tooLargeMessage(selectedFile), "error");
      return;
    }
    if (selectedFile.size === 0) {
      setStatus("That file is empty; there is nothing to encrypt.", "error");
      return;
    }
    if (password.value.length < MIN_PASSWORD) {
      setStatus("The password must be at least " + MIN_PASSWORD + " characters.", "error");
      return;
    }
    if (password.value !== confirmPassword.value) {
      setStatus("The two passwords do not match.", "error");
      return;
    }

    releaseUrls();
    result.hidden = true;
    setStatus("");
    finish(false);
    progressBar.style.width = "0%";
    progressLabel.textContent = "Uploading…";

    var payload = new FormData();
    payload.append("password", password.value);
    payload.append("file", selectedFile, selectedFile.name);

    // Passwords leave the DOM as soon as they are handed to the request
    password.value = "";
    confirmPassword.value = "";

    var request = new XMLHttpRequest();
    request.open("POST", "/api/encrypt", true);
    request.responseType = "blob";

    request.upload.addEventListener("progress", function (event) {
      if (!event.lengthComputable) {
        return;
      }
      var percent = Math.round((event.loaded / event.total) * 100);
      progressBar.style.width = percent + "%";
      progressLabel.textContent =
        percent < 100 ? "Uploading… " + percent + "%" : "Encrypting…";
    });

    request.addEventListener("error", function () {
      finish(true);
      setStatus(
        "The connection dropped before a reply arrived. Check that the service is still " +
          "running, and that the file is within the " + humanSize(maxUploadBytes) + " limit.",
        "error"
      );
    });

    request.addEventListener("abort", function () {
      finish(true);
      setStatus("Upload cancelled.", "error");
    });

    request.addEventListener("timeout", function () {
      finish(true);
      setStatus("The service did not answer in time.", "error");
    });

    request.addEventListener("load", function () {
      finish(true);

      if (request.status !== 200) {
        var reader = new FileReader();
        reader.onload = function () {
          var message = "Request rejected (HTTP " + request.status + ").";
          try {
            var parsed = JSON.parse(reader.result);
            if (parsed && parsed.error) {
              message = parsed.error;
            }
          } catch (ignored) {
            // Non-JSON error bodies keep the generic message
          }
          setStatus(message, "error");
        };
        reader.readAsText(request.response);
        return;
      }

      var keyB64 = request.getResponseHeader("X-Encrypt-Key");
      var keyName = request.getResponseHeader("X-Encrypt-Key-Filename") || "encrypted.key";
      var encName = filenameFromDisposition(
        request.getResponseHeader("Content-Disposition"),
        keyName.replace(/\.key$/, "") + ".enc"
      );

      if (!keyB64) {
        setStatus("The service did not return a key file; nothing was saved.", "error");
        return;
      }

      var raw = atob(keyB64);
      var keyBytes = new Uint8Array(raw.length);
      for (var i = 0; i < raw.length; i++) {
        keyBytes[i] = raw.charCodeAt(i);
      }

      offerDownload(downloadEnc, request.response, encName);
      offerDownload(downloadKey, new Blob([keyBytes], { type: "application/octet-stream" }), keyName);

      result.hidden = false;
      setStatus("Encrypted. Your original file was not touched.", "ok");

      downloadEnc.click();
      // Browsers throttle back-to-back downloads; the buttons stay for manual retry
      window.setTimeout(function () {
        downloadKey.click();
      }, 700);
    });

    request.send(payload);
  });
})();
