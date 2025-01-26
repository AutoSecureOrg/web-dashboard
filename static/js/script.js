// JavaScript to handle form submission
document.getElementById('scanForm').addEventListener('submit', function (event) {
    const urlField = document.getElementById('target_url');
    if (!urlField.value.startsWith('http://') && !urlField.value.startsWith('https://')) {
        alert('Please enter a valid URL starting with http:// or https://');
        event.preventDefault(); // Prevent form submission
    }
});
// tools script:
//network scanner:
const form = document.getElementById('scanner-form');
const scanningIcon = document.getElementById('scanning-icon');
const resultsDiv = document.getElementById('results');
const toggleResults = document.getElementById('toggle-results');
const resultsContent = document.getElementById('results-content');
const scanType = document.getElementById('scan_type');
const singleScan = document.getElementById('single-scan');
const rangeScan = document.getElementById('range-scan');

// Show/hide scan options
scanType.addEventListener('change', () => {
    if (scanType.value === 'single') {
        singleScan.style.display = 'block';
        rangeScan.style.display = 'none';
    } else {
        singleScan.style.display = 'none';
        rangeScan.style.display = 'block';
    }
});

// Handle form submission
form.addEventListener('submit', async (e) => {
    e.preventDefault();
    scanningIcon.classList.remove('hidden'); // Show scanning icon
    resultsContent.innerHTML = "<pre>Scanning...</pre>"; // Update pre element
    toggleResults.classList.add('hidden'); // Hide toggle button

    const formData = new FormData(form);
    const response = await fetch(form.action, {
        method: form.method,
        body: formData,
    });

    scanningIcon.classList.add('hidden'); // Hide scanning icon

    if (response.ok) {
        const data = await response.json();
        resultsContent.innerHTML = `
            <pre>${data.output}</pre>
            <p><a href="${data.pdf_link}" target="_blank">Download PDF Report</a></p>
            <p><a href="${data.word_link}" target="_blank">Download Word Report</a></p>
        `;
        toggleResults.classList.remove('hidden'); // Show toggle button
    } else {
        const errorData = await response.json();
        resultsContent.innerHTML = `
            <pre>${errorData.error}</pre>
        `;
    }
});

// Handle dropdown toggle
toggleResults.addEventListener('click', (e) => {
    if (resultsContent.classList.contains('hidden')) {
        resultsContent.classList.remove('hidden');
        e.target.textContent = 'Hide Results';
    } else {
        resultsContent.classList.add('hidden');
        e.target.textContent = 'Show Results';
    }
});//#endregion














