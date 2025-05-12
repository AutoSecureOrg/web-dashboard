function initializeMobileCrimeData() {
    // Initialize the global variable for crimes
    window.MOBILE_CRIMES_TOP5 = [];
    
    // Look for the results content element
    const resultsContent = document.getElementById('results-content');
    if (!resultsContent) {
        return;
    }
    
    // Get the raw output from the pre code element
    const codeElement = resultsContent.querySelector('pre code');
    if (!codeElement) {
        return;
    }
    
    const outputText = codeElement.textContent || '';
    
    // Call the parser function
    parseMobileScanOutput(outputText);
}

function parseMobileScanOutput(outputText) {
    try {
        // Look for JSON structure in the output
        let jsonStartIndex = outputText.indexOf('{');
        let jsonEndIndex = outputText.lastIndexOf('}');
        if (jsonStartIndex !== -1 && jsonEndIndex !== -1 && jsonEndIndex > jsonStartIndex) {
            let jsonSubstring = outputText.substring(jsonStartIndex, jsonEndIndex + 1);
            
            try {
                // Attempt to parse the JSON substring
                const jsonData = JSON.parse(jsonSubstring);
                
                // Check for crimes array
                if (jsonData.crimes && Array.isArray(jsonData.crimes)) {
                    // Take up to 10 crimes for AI analysis
                    const topCrimes = jsonData.crimes.slice(0, 10);
                    
                    window.MOBILE_CRIMES_TOP5 = topCrimes.map(crime => ({
                        crime: crime.crime || "Unknown issue",
                        label: crime.label || []
                    }));
                }
            } catch (e) {
                // Try more advanced pattern matching
                const crimePattern = /"crime":\s*"([^"]+)".*?"label":\s*\[(.*?)\]/g;
                const extractedCrimes = [];
                let match;
                
                while ((match = crimePattern.exec(outputText)) !== null && extractedCrimes.length < 10) {
                    const crime = match[1];
                    const labelText = match[2];
                    const labels = labelText.split(',').map(l => 
                        l.trim().replace(/"/g, '').trim()
                    ).filter(l => l);
                    
                    extractedCrimes.push({
                        crime: crime,
                        label: labels
                    });
                }
                
                if (extractedCrimes.length > 0) {
                    window.MOBILE_CRIMES_TOP5 = extractedCrimes;
                }
            }
        }
        
        // If still no crimes found from JSON, try parsing the formatted text report
        if (window.MOBILE_CRIMES_TOP5.length === 0) {
            // Look for the table structure
            if (outputText.includes("Rule ID") && outputText.includes("Crime Description")) {
                // Split into lines and find the table section
                const lines = outputText.split('\n');
                let tableStart = -1;
                
                for (let i = 0; i < lines.length; i++) {
                    if (lines[i].includes("Rule ID") && lines[i].includes("Crime Description")) {
                        tableStart = i;
                        break;
                    }
                }
                
                if (tableStart !== -1) {
                    // Skip header lines and parse data rows
                    const crimeRows = [];
                    for (let i = tableStart + 2; i < lines.length && crimeRows.length < 10; i++) {
                        const line = lines[i].trim();
                        if (!line || line.startsWith("-----")) continue;
                        
                        // Attempt to parse the columns
                        const columns = line.split(/\s{2,}/);
                        if (columns.length >= 3) {
                            // Format: Rule ID | Confidence | Score | Crime Description | Labels
                            let crimeDesc = "Unknown";
                            let labels = [];
                            
                            if (columns.length >= 4) {
                                crimeDesc = columns[3].trim();
                            }
                            
                            if (columns.length >= 5) {
                                labels = columns[4].split(',').map(l => l.trim());
                            }
                            
                            crimeRows.push({
                                crime: crimeDesc,
                                label: labels
                            });
                        }
                    }
                    
                    if (crimeRows.length > 0) {
                        window.MOBILE_CRIMES_TOP5 = crimeRows;
                    }
                }
            }
        }
        
        // If no structured data found, extract key phrases from text output
        if (window.MOBILE_CRIMES_TOP5.length === 0) {
            const lines = outputText.split('\n');
            const keyPhrases = [];
            
            // Look for common security patterns
            const securityPatterns = [
                'vulnerability', 'security', 'risk', 'exposure', 'exploit',
                'access', 'permission', 'sensitive', 'data leak', 'encryption',
                'obfuscation', 'intent', 'activity', 'service', 'broadcast'
            ];
            
            for (const line of lines) {
                const trimmedLine = line.trim();
                if (trimmedLine.length < 10) continue; // Skip short lines
                
                // Check if line contains any security patterns
                if (securityPatterns.some(pattern => trimmedLine.toLowerCase().includes(pattern))) {
                    keyPhrases.push({
                        crime: trimmedLine.slice(0, 100) + (trimmedLine.length > 100 ? '...' : ''),
                        label: ['extracted']
                    });
                    
                    if (keyPhrases.length >= 10) break;
                }
            }
            
            if (keyPhrases.length > 0) {
                window.MOBILE_CRIMES_TOP5 = keyPhrases;
            } else {
                // If still nothing, create a special entry for raw analysis
                window.MOBILE_CRIMES_TOP5 = [{
                    crime: "Raw mobile app scan output analysis",
                    label: ["general"],
                    rawOutput: true,
                    output: outputText.substring(0, 3000) // First 3000 chars for analysis
                }];
            }
        }
        
    } catch (error) {
        console.error("Error parsing mobile scan output:", error);
        // Create a fallback entry
        window.MOBILE_CRIMES_TOP5 = [{
            crime: "Error parsing scan output",
            label: ["error"],
            error: error.toString(),
            output: outputText.substring(0, 1000)
        }];
    }
}

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
function getAiInsightMobile(button) {
    // Determine which button was clicked (original or inline)
    const isInlineButton = button.classList.contains('ai-button-inline');
    
    // Get or create response box
    let box = document.getElementById('ai-response-box');
    
    // If it's the inline button, we need to reposition the response box
    if (isInlineButton) {
        // If the box already exists, remove it first
        if (box) {
            box.parentNode.removeChild(box);
        }
        
        // Create a new response box
        box = document.createElement('div');
        box.id = 'ai-response-box';
        box.className = 'ai-response-box';
        box.style.display = 'block';
        box.style.marginTop = '10px';
        box.style.marginBottom = '10px';
        
        // Create spinner
        const spinner = document.createElement('div');
        spinner.className = 'spinner-border';
        spinner.setAttribute('role', 'status');
        
        // Create text container
        const textEl = document.createElement('pre');
        textEl.className = 'ai-text';
        textEl.style.whiteSpace = 'pre-wrap';
        
        // Add elements to box
        box.appendChild(spinner);
        box.appendChild(textEl);
        
        // Insert the box right after the button's container element (span)
        const buttonContainer = button.parentNode;
        buttonContainer.insertAdjacentElement('afterend', box);
    } else {
        // Using the original button, so use the existing response box
        if (!box) return; // Safety check
    }
    
    const spinner = box.querySelector(".spinner-border");
    const text = box.querySelector(".ai-text");

    box.style.display = "block";
    spinner.style.display = "inline-block";
    text.innerText = "Preparing analysis...";

    // Initialize the crime data if it hasn't been done yet
    if (!window.MOBILE_CRIMES_TOP5 || window.MOBILE_CRIMES_TOP5.length === 0) {
        initializeMobileCrimeData();
    }

    // Check for crimes data
    let crimesData = window.MOBILE_CRIMES_TOP5 || [];
    
    // Ensure we have valid data to send
    if (!Array.isArray(crimesData) || crimesData.length === 0) {
        crimesData = [{
            crime: "No specific findings detected",
            label: ["general"]
        }];
    }
    
    fetch('/get-mobile-ai-insight', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            crimes: crimesData
        })
    })
    .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        
        const reader = res.body.getReader();
        const decoder = new TextDecoder("utf-8");
        
        // Clear initial "Preparing analysis..." message
        text.innerText = "";

        return new ReadableStream({
            start(controller) {
                function pump() {
                    reader.read().then(({ done, value }) => {
                        if (done) {
                            spinner.style.display = "none";
                            controller.close();
                            return;
                        }
                        const chunk = decoder.decode(value, { stream: true });
                        text.innerText += chunk;
                        controller.enqueue(value);
                        pump();
                    });
                }
                pump();
            }
        });
    })
    .catch(err => {
        spinner.style.display = "none";
        text.innerText = `Error retrieving AI response: ${err.message}`;
        console.error("AI analysis error:", err);
    });
}
// Add this function to ai-insight.js
function getWiFiRiskAnalysis(button) {
    const responseBox = document.getElementById('wifi-ai-response');
    const spinner = responseBox.querySelector('.spinner');
    const textEl = responseBox.querySelector('.ai-text');

    // Get the risk analysis text from the table
    const riskText = document.querySelector('#vulnTable td:last-child')?.textContent || '';
    if (!riskText.trim()) {
        textEl.textContent = "No risk analysis available for AI to process.";
        responseBox.style.display = 'block';
        return;
    }

    // Show loading state
    responseBox.style.display = 'block';
    spinner.style.display = 'inline-block';
    textEl.textContent = 'Analyzing Wi-Fi risks...';

    fetch('/get-wifi-ai-insight', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ risk_analysis: riskText })
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
                textEl.textContent += decoder.decode(value);
                read();
            });
        }

        read();
    })
    .catch(err => {
        spinner.style.display = "none";
        textEl.textContent = "Error retrieving AI analysis: " + err.message;
        console.error(err);
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

    // Port scan AI insight buttons (Updated selector)
    document.querySelectorAll('.ai-insight-btn-system').forEach(button => {
        button.addEventListener('click', function() {
            // Retrieve data from data-* attributes
            const service = this.dataset.service;
            const version = this.dataset.version;
            const vulnerability = this.dataset.vuln;

            // Call the existing function (which handles finding the row etc.)
            getAiInsightSystem(this, service, version, vulnerability);
        });
    });
    
    // WiFi AI button listener
    document.getElementById('wifi-risk-ai-btn')?.addEventListener('click', function() {
        getWiFiRiskAnalysis(this);
    });

    // Reposition AI button inside the output
    positionAiButtonInOutput();
});

function positionAiButtonInOutput() {
    // Check if we're on the mobile results page
    const resultsContent = document.getElementById('results-content');
    if (!resultsContent) return;
    
    const codeElement = resultsContent.querySelector('pre code');
    if (!codeElement) return;
    
    // Get the existing AI button
    const existingButton = document.querySelector('.ai-button');
    if (!existingButton) return;
    
    // Hide the original button
    existingButton.style.display = 'none';
    
    // Create a new button to place inside the output
    const newButton = document.createElement('button');
    newButton.className = 'ai-button-inline';
    newButton.innerHTML = '🔍 AI Analysis';
    newButton.onclick = function() {
        getAiInsightMobile(this);
    };
    
    // Add some inline styles for the button
    newButton.style.cssText = 'background-color: #262e3d; color: #fff; border: 1px solid #4b566b; ' +
                             'padding: 4px 10px; font-size: 0.85rem; cursor: pointer; border-radius: 4px; ' +
                             'margin: 5px 0; display: inline-block;';
    
    // Try to find the "Detected Findings (Crimes):" line
    let foundHeader = false;
    
    // First approach: look through text nodes
    const textContent = codeElement.textContent;
    const findingsIndex = textContent.indexOf('Detected Findings (Crimes):');
    if (findingsIndex >= 0) {
        foundHeader = true;
        
        // Find the next newline character after the header
        const newlineIndex = textContent.indexOf('\n', findingsIndex);
        if (newlineIndex >= 0) {
            // Split the content into before and after this point
            const beforeText = textContent.substring(0, newlineIndex + 1);
            const afterText = textContent.substring(newlineIndex + 1);
            
            // Clear the code element and rebuild it with our button in the middle
            codeElement.innerHTML = '';
            
            // First part
            const firstPart = document.createTextNode(beforeText);
            codeElement.appendChild(firstPart);
            
            // Add the button
            const buttonContainer = document.createElement('span');
            buttonContainer.appendChild(newButton);
            buttonContainer.appendChild(document.createElement('br'));
            codeElement.appendChild(buttonContainer);
            
            // Second part
            const secondPart = document.createTextNode(afterText);
            codeElement.appendChild(secondPart);
        }
    }
    
    // If we couldn't reposition the button, make the original visible again
    if (!foundHeader) {
        existingButton.style.display = 'block';
    }
    
    // Remove the existing response box if it exists (it will be recreated when needed)
    const existingResponseBox = document.getElementById('ai-response-box');
    if (existingResponseBox) {
        existingResponseBox.parentNode.removeChild(existingResponseBox);
    }
}
