document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("startAudit").addEventListener("click", function () {

        const progressArea = document.getElementById("progressArea");

        progressArea.innerHTML = `
            <div class="alert alert-info">
                Running audit... please wait.
            </div>
        `;

        const payload = {
            ip: document.getElementById("ip").value,
            username: document.getElementById("username").value,
            password: document.getElementById("password").value,
            auth: document.getElementById("auth").value
        };

        fetch("/api/audit/start", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        })
        .then(response => response.json())
        .then(result => {

            if (result.status === "success") {
                progressArea.innerHTML = `
                    <div class="alert alert-success">
                        Audit completed successfully. Opening results...
                    </div>
                `;

                window.location.href = result.redirect;
            } else {
                progressArea.innerHTML = `
                    <div class="alert alert-danger">
                        ${result.message || "Audit failed"}
                    </div>
                `;
            }
        })
        .catch(error => {
            progressArea.innerHTML = `
                <div class="alert alert-danger">
                    Request failed: ${error}
                </div>
            `;
        });
    });
});