const hamburger = document.querySelector(".hamburger");
const navMenu = document.querySelector(".nav-menu");

// Event listener for the hamburger menu to toggle mobile menu
hamburger.addEventListener("click", mobileMenu);
function toggleMenu() {
    const navMenu = document.getElementById('navMenu');
    navMenu.classList.toggle('active');

    const hamburger = document.querySelector('.hamburger');
    hamburger.classList.toggle('active');
}
function mobileMenu() {
    hamburger.classList.toggle("active"); 
    navMenu.classList.toggle("active"); 
}

// Close mobile menu when a nav link is clicked
const navLink = document.querySelectorAll(".nav-link");
navLink.forEach(n => n.addEventListener("click", closeMenu));

function closeMenu() {
    hamburger.classList.remove("active"); 
    navMenu.classList.remove("active"); 
}

// Function to toggle dropdown menu visibility
function toggleDropdown() {
    const dropdown = document.getElementById("toolsDropdown");
    dropdown.classList.toggle("active"); 
}

const dropdownButton = document.querySelector('.dropdown-button');
if (dropdownButton) {
    dropdownButton.addEventListener("click", toggleDropdown);
}

window.onclick = function(event) {
    if (!event.target.closest('.dropdown') && window.innerWidth > 768) {
        const dropdown = document.getElementById("toolsDropdown");
    
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