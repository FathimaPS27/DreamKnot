document.addEventListener('DOMContentLoaded', function() {

    // Search functionality
    const searchInput = document.querySelector('.hero .filters input[type="text"]');
    searchInput.addEventListener('keypress', function(event) {
        if (event.key === 'Enter') {
            alert('Search: ' + searchInput.value);
        }
    });

    // Filter button click
    const filterButton = document.querySelector('.filter-options button');
    filterButton.addEventListener('click', function() {
        alert('Filter applied');
    });

    // Range input change
    const rangeInput = document.querySelector('.filter-options input[type="range"]');
    rangeInput.addEventListener('input', function() {
        alert('Range value: ' + rangeInput.value);
    });

    // Smooth scroll for navigation links
    const navLinks = document.querySelectorAll('nav a');
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href').substring(1);
            document.getElementById(targetId).scrollIntoView({
                behavior: 'smooth'
            });
        });
    });

});
document.addEventListener("DOMContentLoaded", function() {
    // Add any JavaScript interactivity here if needed
    console.log("Page Loaded");
});

