const hamburger = document.querySelector(".hamburger");
const navMenu = document.querySelector(".nav-menu");

// Event listener for the hamburger menu to toggle mobile menu
hamburger.addEventListener("click", mobileMenu);

function mobileMenu() {
    hamburger.classList.toggle("active"); // Toggle the active class for hamburger
    navMenu.classList.toggle("active"); // Toggle the active class for the navigation menu
}

// Close mobile menu when a nav link is clicked
const navLink = document.querySelectorAll(".nav-link");
navLink.forEach(n => n.addEventListener("click", closeMenu));

function closeMenu() {
    hamburger.classList.remove("active"); // Remove active class from hamburger
    navMenu.classList.remove("active"); // Remove active class from nav menu
}

// Function to toggle dropdown menu visibility
function toggleDropdown() {
    const dropdown = document.getElementById("toolsDropdown");
    dropdown.classList.toggle("active"); // Toggle the active class for the dropdown
}

// Event listener for clicks on dropdown button (add this button to your HTML)
const dropdownButton = document.querySelector('.dropdown-button'); // Adjust selector if necessary
if (dropdownButton) {
    dropdownButton.addEventListener("click", toggleDropdown);
}

// Close the dropdown when clicking outside, but don't close the mobile menu
window.onclick = function(event) {
    // Check if the click is outside the dropdown and if the window width is greater than 768px
    if (!event.target.closest('.dropdown') && window.innerWidth > 768) {
        const dropdown = document.getElementById("toolsDropdown");
        // Close dropdown if it's active
        if (dropdown && dropdown.classList.contains('active')) {
            dropdown.classList.remove('active');
        }
    }
};

window.onresize = function() {
    const dropdown = document.getElementById("toolsDropdown");
    if (window.innerWidth > 768 && dropdown && dropdown.classList.contains('active')) {
        dropdown.classList.remove('active'); // Close dropdown on larger screens
    }
};
