// JavaScript to handle form submission (Ensure element exists)
const scanForm = document.getElementById('scanForm');
if (scanForm) {
    scanForm.addEventListener('submit', function (event) {
    const urlField = document.getElementById('target_url');
        if (urlField && (!urlField.value.startsWith('http://') && !urlField.value.startsWith('https://'))) {
        alert('Please enter a valid URL starting with http:// or https://');
        event.preventDefault(); // Prevent form submission
    }
});
}

// tools script:
// network scanner: (Ensure elements exist)
const networkScannerForm = document.getElementById('scanner-form');
if (networkScannerForm) {
const scanningIcon = document.getElementById('scanning-icon');
const resultsDiv = document.getElementById('results');
const toggleResults = document.getElementById('toggle-results');
const resultsContent = document.getElementById('results-content');
const scanType = document.getElementById('scan_type');
const singleScan = document.getElementById('single-scan');
const rangeScan = document.getElementById('range-scan');

    // Get references to the actual input fields
    const targetIpInput = document.getElementById('target_ip');
    const startIpInput = document.getElementById('start_ip');
    const endIpInput = document.getElementById('end_ip');

    // Show/hide scan options based on initial value and changes
    const updateScanOptionsVisibility = () => {
        if (scanType && singleScan && rangeScan && targetIpInput && startIpInput && endIpInput) {
            if (scanType.value === 'single') {
                singleScan.style.display = 'block';
                rangeScan.style.display = 'none';
                targetIpInput.disabled = false; // Enable single IP input
                startIpInput.disabled = true;   // Disable range inputs
                endIpInput.disabled = true;
            } else { // Assuming 'range'
                singleScan.style.display = 'none';
                rangeScan.style.display = 'block';
                targetIpInput.disabled = true;    // Disable single IP input
                startIpInput.disabled = false;  // Enable range inputs
                endIpInput.disabled = false;
            }
        } else {
            console.warn("Network scanner form elements not found for visibility/disabling logic.");
        }
    };

    if (scanType) {
        scanType.addEventListener('change', updateScanOptionsVisibility);
        // Initial check in case the default isn't 'single'
        updateScanOptionsVisibility();
    }


// Handle form submission
    networkScannerForm.addEventListener('submit', (e) => {
        console.log("Network Scanner form submitted. Allowing standard navigation..."); // Log: Entry

        // Show scanning icon briefly before navigation
        const scanningIcon = document.getElementById('scanning-icon');
        if (scanningIcon) {
            scanningIcon.classList.remove('hidden');
        }
});

// Handle dropdown toggle
    if (toggleResults && resultsContent) {
toggleResults.addEventListener('click', (e) => {
    if (resultsContent.classList.contains('hidden')) {
        resultsContent.classList.remove('hidden');
        e.target.textContent = 'Hide Results';
    } else {
        resultsContent.classList.add('hidden');
        e.target.textContent = 'Show Results';
    }
        });
    }
}

function redirectToTool(toolPage) {
    window.location.href = toolPage;
}

document.addEventListener('DOMContentLoaded', () => {
    console.log("DOM fully loaded and parsed for home page features."); // Debug log

    const featureLinks = document.querySelectorAll('.feature-nav a');
    const detailsModal = document.getElementById('details-modal');
    const modalContent = document.getElementById('modal-content');
    const detailsContentContainer = document.getElementById('details-content-container');
    const closeBtn = document.getElementById('close-btn');
    const bgVideo = document.getElementById('bg-video');
    const titleTrigger = document.getElementById('title-trigger');
    const mouseMoveStrength = 50;

    // Check if essential elements exist
    if (!featureLinks.length || !detailsModal || !modalContent || !detailsContentContainer || !closeBtn) {
         console.error("Essential modal elements not found!");
         return; // Stop execution if key elements are missing
    }

    console.log(`Found ${featureLinks.length} feature links.`); // Debug log

    let activeLink = null;
    let isTouchDevice = false;
    let touchTimeout = null;

    // Detect touch device
    window.addEventListener('touchstart', function onFirstTouch() {
        isTouchDevice = true;
        console.log("Touch device detected."); // Debug log
        window.removeEventListener('touchstart', onFirstTouch);
    }, { once: true }); // Use { once: true } for efficiency

    // Feature navigation and modal handling
    featureLinks.forEach((link, index) => {
        console.log(`Attaching listeners to link ${index + 1}:`, link); // Debug log

        // Handle click/touch for modal
        link.addEventListener('click', (e) => {
            e.preventDefault();
            console.log("Link clicked:", link.dataset.target); // Debug log

            // Only handle click for desktop or after animation for mobile
            if (!isTouchDevice || link.classList.contains('show-card')) {
                console.log("Processing click..."); // Debug log
                const targetId = link.getAttribute('data-target');
                const sourceContentElement = document.getElementById(targetId);
                const targetUrl = link.dataset.url; // Get URL from data-url attribute

                console.log("Target ID:", targetId);
                console.log("Source Element:", sourceContentElement);
                console.log("Target URL:", targetUrl);

                if (sourceContentElement) {
                    // Clear existing content
                    detailsContentContainer.innerHTML = '';

                    // Clone and append feature details
                    const clonedContent = sourceContentElement.cloneNode(true);
                    clonedContent.style.display = 'block';
                    detailsContentContainer.appendChild(clonedContent);
                    console.log("Appended content to modal."); // Debug log

                    // Remove existing test button if present
                    const existingTestBtn = modalContent.querySelector('.test-btn');
                    if (existingTestBtn) {
                        existingTestBtn.remove();
                        console.log("Removed existing test button."); // Debug log
                    }

                    // Create and add the "Test" button if a data-url attribute exists
                    if (targetUrl) {
                        const testBtn = document.createElement('button');
                        testBtn.textContent = 'Test';
                        testBtn.classList.add('modal-button', 'test-btn'); // Add classes for styling
                        testBtn.onclick = () => {
                            console.log("Test button clicked, redirecting to:", targetUrl);
                            window.location.href = targetUrl; // Use the URL from data-url
                        };
                        modalContent.appendChild(testBtn);
                         console.log("Added new test button."); // Debug log
                    } else {
                        console.log("No target URL found, Test button not added."); // Debug log
                    }

                    detailsModal.classList.add('active');
                    console.log("Modal activated."); // Debug log
                } else {
                    console.error("Source content element not found for target ID:", targetId);
                }
            } else {
                 console.log("Click ignored (touch device, card not shown yet)."); // Debug log
            }
        });

        // Handle touch for glitch effect
        if ('ontouchstart' in window) {
            link.addEventListener('touchstart', (e) => {
                e.preventDefault();
                console.log("Link touched:", link.dataset.target); // Debug log

                // Clear any existing timeouts
                if (touchTimeout) {
                    clearTimeout(touchTimeout);
                }

                // Remove classes from previously active elements
                if (activeLink && activeLink !== link) {
                    activeLink.classList.remove('glitch-only', 'show-card');
                }
                if (titleTrigger && titleTrigger.classList.contains('show-card')) {
                    titleTrigger.classList.remove('glitch-only', 'show-card');
                }

                // Start glitch animation
                link.classList.add('glitch-only');
                activeLink = link;
                console.log("Glitch effect added."); // Debug log

                // After glitch animation, show card
                touchTimeout = setTimeout(() => {
                    link.classList.remove('glitch-only');
                    link.classList.add('show-card');
                    console.log("Show card class added, triggering click..."); // Debug log
                    // Trigger click event after showing card
                    link.click();
                }, 500); // 500ms delay for glitch effect
            });
        }
    });

    // Title trigger touch handling
    if (titleTrigger && 'ontouchstart' in window) {
        titleTrigger.addEventListener('touchstart', (e) => {
            e.preventDefault();
            console.log("Title touched."); // Debug log

            // Clear any existing timeouts
            if (touchTimeout) {
                clearTimeout(touchTimeout);
            }

            // Remove classes from previously active elements
            if (activeLink) {
                activeLink.classList.remove('glitch-only', 'show-card');
                activeLink = null;
            }
            titleTrigger.classList.remove('glitch-only', 'show-card');

            // Start glitch animation
            titleTrigger.classList.add('glitch-only');
            console.log("Title glitch added."); // Debug log

            // After glitch animation, show info card
            touchTimeout = setTimeout(() => {
                titleTrigger.classList.remove('glitch-only');
                titleTrigger.classList.add('show-card');
                 console.log("Title show card added."); // Debug log
            }, 500); // 500ms delay
        });

        // Add touch event to close info card when touching outside
        document.addEventListener('touchstart', (e) => {
            if (titleTrigger.classList.contains('show-card') &&
                !titleTrigger.contains(e.target) &&
                !titleTrigger.querySelector('.info-card')?.contains(e.target)) { // Ensure click isn't inside card
                console.log("Touch outside title while card shown, hiding card."); // Debug log
                titleTrigger.classList.remove('glitch-only', 'show-card');
            }
        });
    }

    // Add "modal-button" class to existing close button for consistent styling
    if (closeBtn) {
        closeBtn.classList.add('modal-button');
    }

    closeBtn.addEventListener('click', () => {
        console.log("Close button clicked."); // Debug log
        detailsModal.classList.remove('active');
        // Remove the test button when closing the modal
        const testBtn = modalContent.querySelector('.test-btn');
        if (testBtn) {
             testBtn.remove();
             console.log("Test button removed on close."); // Debug log
        }
        // Delay clearing content to allow fade-out transition
        setTimeout(() => {
            if (!detailsModal.classList.contains('active')) {
                detailsContentContainer.innerHTML = '';
                 console.log("Modal content cleared after transition."); // Debug log
            }
        }, 400); // Match transition duration (adjust if CSS transition time changes)
    });

    detailsModal.addEventListener('click', (e) => {
        // Close modal if backdrop is clicked (e.target is the modal overlay itself)
        if (e.target === detailsModal) {
            console.log("Modal backdrop clicked."); // Debug log
            closeBtn.click();
        }
    });

    document.addEventListener('keydown', (e) => {
        // Close modal on Escape key press
        if (e.key === 'Escape' && detailsModal.classList.contains('active')) {
             console.log("Escape key pressed."); // Debug log
            closeBtn.click();
        }
    });

    // Mouse move effect for video background
    if (bgVideo) {
        window.addEventListener('mousemove', (e) => {
            const xPos = (e.clientX / window.innerWidth - 0.5) * mouseMoveStrength;
            const yPos = (e.clientY / window.innerHeight - 0.5) * mouseMoveStrength;

            if (bgVideo.parentElement) {
                bgVideo.parentElement.style.transform = `translate(${-xPos}px, ${-yPos}px)`;
            }
        });
        console.log("Mouse move effect for background video initialized."); // Debug log
    } else {
        console.warn("Background video element (#bg-video) not found.");
    }

    // Grained.js Initialization
    function initGrainedTexture() {
        // Check if Grained exists before calling it
        if (typeof grained === 'function') {
            const options = {
                animate: true,
                patternWidth: 200,
                patternHeight: 200,
                grainDensity: 3,
                grainWidth: 1,
                grainHeight: 1,
                grainOpacity: window.matchMedia("(min-width: 992px)").matches ? 0.35 : 0.15
            };
            const grainOverlay = document.getElementById('grain-overlay');
            if (grainOverlay) {
                grained('#grain-overlay', options);
                console.log("Grained texture initialized."); // Debug log
            } else {
                 console.warn("Grain overlay element (#grain-overlay) not found.");
            }
        } else {
            console.warn("Grained library not loaded or function not found.");
        }
    }

    initGrainedTexture();

    let resizeTimer;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
            console.log("Window resized, re-initializing Grained texture."); // Debug log
            initGrainedTexture();
        }, 250);
    });

    // Generic handler for buttons with data-url attribute
    document.querySelectorAll('button[data-url]').forEach(button => {
        console.log("Attaching redirect listener to button:", button);
        const targetUrl = button.dataset.url;
        if (targetUrl) {
            button.addEventListener('click', () => {
                console.log(`Button with data-url clicked. Redirecting to: ${targetUrl}`);
                window.location.href = targetUrl;
            });
        } else {
            console.warn("Button found with data-url attribute, but the attribute is empty:", button);
        }
    });

});
