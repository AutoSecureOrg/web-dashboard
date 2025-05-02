function getAiInsightSystem(button, service, version, vulnerability) {
    const aiRow = button.closest("tr").nextElementSibling;
    const responseBox = aiRow.querySelector(".ai-response-box");
    const spinner = responseBox.querySelector(".spinner-border");
    const textEl = responseBox.querySelector(".ai-text");

    aiRow.style.display = "table-row";
    spinner.style.display = "inline-block";
    textEl.innerText = "";

    fetch('/get-system-ai-insight', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ service, version, vuln: vulnerability })
    })
    .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const reader = response.body.getReader();
        const decoder = new TextDecoder();

        function read() {
            reader.read().then(({ done, value }) => {
                if (done) {
                    spinner.style.display = "none";
                    return;
                }
                textEl.innerText += decoder.decode(value);
                read();
            });
        }

        read();
    })
    .catch(err => {
        spinner.style.display = "none";
        textEl.innerText = "Error retrieving AI response.";
        console.error(err);
    });
}
function getWebScanInsight(button, payload) {
    const box = button.nextElementSibling;
    const spinner = box.querySelector(".spinner-border");
    const responseText = box.querySelector(".ai-response");

    box.style.display = 'block';
    spinner.style.display = 'inline-block';
    responseText.textContent = 'Thinking...';

    console.log("Sending web insight request with payload:", payload.substring(0, 50) + "...");

    fetch('/get-web-ai-insight', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload })
    })
    .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const reader = response.body.getReader();
        const decoder = new TextDecoder();

        function read() {
            reader.read().then(({ done, value }) => {
                if (done) {
                    spinner.style.display = 'none';
                    return;
                }
                // Clear "Thinking..." on first response chunk
                if (responseText.textContent === 'Thinking...') {
                    responseText.textContent = '';
                }
                responseText.textContent += decoder.decode(value);
                read();
            });
        }
        read();
    })
    .catch(err => {
        spinner.style.display = 'none';
        responseText.textContent = "Error loading AI response.";
        console.error(err);
    });
}

// Function for Mobile App AI remediation advice
function getMobileRemediationAdvice(appName, packageName, version, findings) {
    const aiResponse = document.getElementById('aiResponse');
    const aiLoading = document.getElementById('aiLoading');
    const aiContent = document.getElementById('aiContent');
    const aiPre = aiContent.querySelector('pre');

    aiResponse.classList.remove('d-none');
    aiLoading.classList.remove('d-none');
    aiContent.classList.add('d-none');

    // Prepare data for AI request
    const findingsData = {
        app_name: appName,
        package: packageName,
        version: version,
        findings: findings
    };

    // Make API call
    fetch('/get-mobile-ai-insight', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(findingsData)
    })
    .then(response => {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let result = '';

        function read() {
            return reader.read().then(({done, value}) => {
                if (done) {
                    aiLoading.classList.add('d-none');
                    aiContent.classList.remove('d-none');
                    return;
                }

                // Append the new chunk to the result
                result += decoder.decode(value, {stream: true});
                aiPre.textContent = result;

                // Keep reading
                return read();
            });
        }

        // Start reading the stream
        return read();
    })
    .catch(error => {
        aiLoading.classList.add('d-none');
        aiContent.classList.remove('d-none');
        aiPre.textContent = `Error: ${error.message}`;
    });
}

// Add event listeners when document is loaded
document.addEventListener('DOMContentLoaded', function() {
    // For web scan AI fix buttons
    document.querySelectorAll('.ai-fix-btn').forEach(button => {
        button.addEventListener('click', function() {
            const payload = this.getAttribute('data-payload');
            getWebScanInsight(this, payload);
        });
    });

    // Mobile AI remediation button
    const askAIBtn = document.getElementById('askAIBtn');
    if (askAIBtn) {
        askAIBtn.addEventListener('click', function() {
            // Get the data attributes from the button
            const appName = this.getAttribute('data-app-name');
            const packageName = this.getAttribute('data-package-name');
            const version = this.getAttribute('data-version');
            const findings = JSON.parse(this.getAttribute('data-findings'));

            getMobileRemediationAdvice(appName, packageName, version, findings);
        });
    }

    // Port scan AI insight buttons (Updated selector)
    document.querySelectorAll('.ai-insight-btn-system').forEach(button => {
        button.addEventListener('click', function() {
            // Retrieve data from data-* attributes
            const service = this.dataset.service;
            const version = this.dataset.version;
            const vulnerability = this.dataset.vuln;

            console.log(`System AI Insight requested for: ${service} ${version}, Vuln: ${vulnerability.substring(0, 50)}...`); // Debug log

            // Call the existing function (which handles finding the row etc.)
            getAiInsightSystem(this, service, version, vulnerability);
        });
    });
});
