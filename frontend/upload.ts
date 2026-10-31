// ARCHIVE UPLOADS
//
// The restore page's upload form (data-upload) sends the chosen file as the raw body of
// one PUT /restore/uploads through XMLHttpRequest: htmx 4 is fetch-based, and fetch
// reports no upload progress. The CSRF token goes in the X-CSRF-Token header, as htmx
// sends it. The server answers 201 with JSON, or an error in plain text (an HTML error
// page from the role or CSRF checks shows its status only). After a 201 the restore of
// an unencrypted upload starts at once; an encrypted one goes to the list of uploads,
// where a passphrase can be entered first. The listener sits on the document, so a form that htmx
// swapped in later works too.

{
  let uploading = false;

  const describe = (xhr: XMLHttpRequest): string => {
    const type = xhr.getResponseHeader("content-type") ?? "";
    if (type.startsWith("text/plain") && xhr.responseText) {
      return xhr.responseText; // shown with textContent only
    }
    return `The upload failed (HTTP ${xhr.status}). Reload the page and try again.`;
  };

  // Starts the restore of the upload as its "Verify and restore" button would: a normal
  // form post, so the plan page (or the restore page with an error) replaces this one.
  const verify = (id: number, csrf: string): void => {
    const post = document.createElement("form");
    post.method = "post";
    post.action = `/restore/from-upload/${id}`;
    const token = document.createElement("input");
    token.type = "hidden";
    token.name = "csrf_token";
    token.value = csrf;
    post.append(token);
    document.body.append(post);
    post.submit();
  };

  const upload = (form: HTMLFormElement): void => {
    const input = form.querySelector<HTMLInputElement>("input[type=file]");
    const button = form.querySelector<HTMLButtonElement>("button[type=submit]");
    const bar = form.querySelector<HTMLProgressElement>("progress");
    const status = form.querySelector<HTMLElement>("[data-upload-status]");
    const file = input?.files?.[0];
    if (!input || !button || !bar || !status || uploading) {
      return;
    }
    const say = (message: string): void => {
      status.textContent = message;
    };
    if (!file) {
      say("Choose an archive first.");
      return;
    }
    const limit = Number(form.dataset["maxBytes"]);
    if (file.size === 0 || file.size > limit) {
      say(`The file must hold between 1 byte and ${limit / 1e9} GB.`);
      return;
    }
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", `${form.action}?name=${encodeURIComponent(file.name)}`);
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.setRequestHeader("X-CSRF-Token", form.dataset["csrf"] ?? "");
    xhr.upload.addEventListener("progress", (event) => {
      if (event.lengthComputable) {
        bar.value = event.loaded / event.total;
      }
    });
    const done = (message: string): void => {
      uploading = false;
      input.disabled = button.disabled = false;
      bar.hidden = true;
      say(message);
    };
    xhr.addEventListener("load", () => {
      if (new URL(xhr.responseURL).pathname === "/login") {
        window.location.assign("/login"); // the session ended meanwhile
      } else if (xhr.status === 201) {
        const stored = JSON.parse(xhr.responseText) as { id: number; name: string };
        if (stored.name.endsWith(".age")) {
          // It may need a passphrase: the list of uploads asks for one first.
          done(`Uploaded ${stored.name}.`);
          window.location.assign("/restore"); // a full load lists it
        } else {
          done(`Uploaded ${stored.name}. Verifying it next.`);
          verify(stored.id, form.dataset["csrf"] ?? "");
        }
      } else {
        done(describe(xhr));
      }
    });
    xhr.addEventListener("abort", () => {
      done("The upload was cancelled.");
    });
    xhr.addEventListener("error", () => {
      done("The upload was cut off. Check the connection and the free space on drydock's staging disk, then try again.");
    });
    uploading = true;
    input.disabled = button.disabled = true;
    bar.value = 0;
    bar.hidden = false;
    say(`Uploading ${file.name}. Keep this page open until it finishes.`);
    xhr.send(file);
  };

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (form instanceof HTMLFormElement && form.hasAttribute("data-upload")) {
      event.preventDefault();
      upload(form);
    }
  });

  window.addEventListener("beforeunload", (event) => {
    if (uploading) {
      event.preventDefault(); // leaving would cancel the upload
    }
  });
}
