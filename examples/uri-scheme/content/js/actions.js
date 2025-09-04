// Interactive JavaScript for the Virtual Host Mapping Demo
document.addEventListener('DOMContentLoaded', function() {
    // Initialize the page
    displayURIInfo();
    setupEventListeners();
    
    // Show initial message
    showMessage('Page loaded successfully! All assets served via custom URI scheme.', 'success');
});

function displayURIInfo() {
    // Display current URI information
    const url = window.location.href;
    const urlObj = new URL(url);
    
    document.getElementById('current-url').textContent = url;
    document.getElementById('scheme').textContent = urlObj.protocol.replace(':', '');
    document.getElementById('host').textContent = urlObj.host;
    document.getElementById('path').textContent = urlObj.pathname;
}

function setupEventListeners() {
    // Theme toggle button
    document.getElementById('color-btn').addEventListener('click', function() {
        toggleTheme();
    });
    
    // Counter button
    document.getElementById('counter-btn').addEventListener('click', function() {
        incrementCounter();
    });
    
    // Alert button
    document.getElementById('alert-btn').addEventListener('click', function() {
        showAlert();
    });
}

function toggleTheme() {
    const body = document.body;
    const isDark = body.classList.contains('dark-theme');
    
    if (isDark) {
        body.classList.remove('dark-theme');
        showMessage('Switched to light theme!', 'info');
    } else {
        body.classList.add('dark-theme');
        showMessage('Switched to dark theme!', 'info');
    }
}

function incrementCounter() {
    const counterElement = document.getElementById('counter');
    let currentCount = parseInt(counterElement.textContent);
    currentCount++;
    counterElement.textContent = currentCount;
    
    showMessage(`Counter incremented to ${currentCount}!`, 'success');
}

function showAlert() {
    const messages = [
        'Hello from the custom URI scheme!',
        'This JavaScript is loaded via virtual host mapping!',
        'All assets are served through your Go webview!',
        'The URI scheme is working perfectly!'
    ];
    
    const randomMessage = messages[Math.floor(Math.random() * messages.length)];
    showMessage(randomMessage, 'info');
}

function showMessage(text, type) {
    const messageArea = document.getElementById('message-area');
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}`;
    messageDiv.textContent = text;
    
    // Add timestamp
    const timestamp = new Date().toLocaleTimeString();
    messageDiv.textContent += ` (${timestamp})`;
    
    messageArea.appendChild(messageDiv);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (messageDiv.parentNode) {
            messageDiv.remove();
        }
    }, 5000);
}

// Add some interactive features
let clickCount = 0;
document.addEventListener('click', function(e) {
    // Don't count button clicks (they have their own handlers)
    if (e.target.tagName === 'BUTTON') return;
    
    clickCount++;
    if (clickCount % 10 === 0) {
        showMessage(`You've clicked ${clickCount} times on the page!`, 'info');
    }
});

// Add keyboard shortcuts
document.addEventListener('keydown', function(e) {
    switch(e.key) {
        case 't':
        case 'T':
            if (e.ctrlKey) {
                e.preventDefault();
                toggleTheme();
            }
            break;
        case 'c':
        case 'C':
            if (e.ctrlKey) {
                e.preventDefault();
                incrementCounter();
            }
            break;
        case 'a':
        case 'A':
            if (e.ctrlKey) {
                e.preventDefault();
                showAlert();
            }
            break;
    }
});

// Add some visual feedback for the demo
function addVisualEffects() {
    // Add a subtle pulse animation to the header
    const header = document.querySelector('header');
    header.style.animation = 'pulse 2s infinite';
    
    // Add CSS for the pulse animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.02); }
            100% { transform: scale(1); }
        }
    `;
    document.head.appendChild(style);
}

// Initialize visual effects after a short delay
setTimeout(addVisualEffects, 1000);

// Console logging for debugging
console.log('Virtual Host Mapping Demo JavaScript loaded successfully!');
console.log('Current URL:', window.location.href);
console.log('All assets loaded via custom URI scheme from nested directories');
console.log('CSS: css/styles/style.css');
console.log('JS: js/actions.js');
