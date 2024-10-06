// clockwork.js

// Update the clock and related elements
function updateClock() {
    console.log("updateClock called"); // Debugging statement
    const now = new Date();

    // Update local time
    const localTimeElement = document.getElementById('local-time');
    const timeOptions = { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false };
    if (localTimeElement) {
        localTimeElement.textContent = now.toLocaleTimeString([], timeOptions);
    }

    // Update date
    const currentDateElement = document.getElementById('current-date');
    const dateOptions = { year: 'numeric', month: 'long', day: 'numeric' }; // Ensure 'month' is 'long'
    if (currentDateElement) {
        const formattedDate = now.toLocaleDateString(undefined, dateOptions);
        console.log("Formatted Date:", formattedDate); // Debugging statement
        currentDateElement.textContent = formattedDate;
    }

    // Update day of the week
    const dayOfWeekElement = document.getElementById('day-of-week');
    const dayOptions = { weekday: 'long' };
    if (dayOfWeekElement) {
        dayOfWeekElement.textContent = now.toLocaleDateString(undefined, dayOptions);
    }

    // Update time zone
    const timeZoneElement = document.getElementById('time-zone');
    const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    if (timeZoneElement) {
        timeZoneElement.textContent = `Time Zone: ${timeZone}`;
    }

    // Update greeting
    const greetingElement = document.getElementById('greeting');
    const hour = now.getHours();
    let greeting;
    if (hour >= 5 && hour < 12) {
        greeting = 'Good morning!';
    } else if (hour >= 12 && hour < 18) {
        greeting = 'Good afternoon!';
    } else if (hour >= 18 && hour < 22) {
        greeting = 'Good evening!';
    } else {
        greeting = 'Good night!';
    }
    if (greetingElement) {
        greetingElement.textContent = greeting;
    }

    // Update background color
    const clockContainer = document.querySelector('.clock-container');
    if (clockContainer) {
        let backgroundColor;
        if (hour >= 6 && hour < 12) {
            backgroundColor = 'var(--background-color-morning)'; // Morning
        } else if (hour >= 12 && hour < 18) {
            backgroundColor = 'var(--background-color-afternoon)'; // Afternoon
        } else if (hour >= 18 && hour < 21) {
            backgroundColor = 'var(--background-color-evening)'; // Evening
        } else {
            backgroundColor = 'var(--background-color-night)'; // Night
        }
        clockContainer.style.setProperty('--background-color', backgroundColor);
    }
}

// Show time since last visit
function updateLastVisit() {
    console.log("updateLastVisit called"); // Debugging statement
    const lastVisitMessageElement = document.getElementById('last-visit-message');
    const now = new Date();
    const lastVisit = localStorage.getItem('lastVisit');

    if (lastVisit) {
        const previousVisit = new Date(lastVisit);
        const timeDifference = now - previousVisit;
        const days = Math.floor(timeDifference / (1000 * 60 * 60 * 24));
        const hours = Math.floor((timeDifference / (1000 * 60 * 60)) % 24);
        const minutes = Math.floor((timeDifference / (1000 * 60)) % 60);

        let message = 'Welcome back! You last visited ';
        if (days > 0) {
            message += `${days} day(s) `;
        }
        if (hours > 0) {
            message += `${hours} hour(s) `;
        }
        if (minutes > 0 && days === 0) {
            message += `${minutes} minute(s) `;
        }
        message += 'ago.';
        if (lastVisitMessageElement) {
            lastVisitMessageElement.textContent = message;
        }
    } else {
        if (lastVisitMessageElement) {
            lastVisitMessageElement.textContent = 'Welcome to my website!';
        }
    }

    // Update last visit time
    localStorage.setItem('lastVisit', now);
}

// Draw analog clock with fancy animations
function drawAnalogClock() {
    console.log("drawAnalogClock called"); // Debugging statement
    const canvas = document.getElementById('analog-clock');
    if (!canvas) {
        console.error("Canvas element with id 'analog-clock' not found.");
        return;
    }
    const ctx = canvas.getContext('2d');
    if (!ctx) {
        console.error("2D context not supported or canvas already initialized.");
        return;
    }

    const radius = canvas.width / 2;
    ctx.clearRect(0, 0, canvas.width, canvas.height); // Clear any existing drawings
    ctx.translate(radius, radius);
    const clockRadius = radius * 0.90;

    function drawClock() {
        drawFace(ctx, clockRadius);
        drawNumbers(ctx, clockRadius);
        drawTime(ctx, clockRadius);
        requestAnimationFrame(drawClock);
    }

    function drawFace(ctx, radius) {
        console.log("drawFace called"); // Debugging statement
        // Clear the canvas
        ctx.clearRect(-radius, -radius, canvas.width, canvas.height);

        // Outer circle
        ctx.beginPath();
        ctx.arc(0, 0, radius, 0, 2 * Math.PI);
        ctx.fillStyle = '#333';
        ctx.fill();

        // Gradient border
        const grad = ctx.createRadialGradient(0, 0, radius * 0.95, 0, 0, radius * 1.05);
        grad.addColorStop(0, '#fff');
        grad.addColorStop(0.5, 'var(--primary-color)');
        grad.addColorStop(1, 'var(--secondary-color)');
        ctx.strokeStyle = grad;
        ctx.lineWidth = radius * 0.05;
        ctx.stroke();

        // Center dot
        ctx.beginPath();
        ctx.arc(0, 0, radius * 0.05, 0, 2 * Math.PI);
        ctx.fillStyle = '#fff';
        ctx.fill();
    }

    function drawNumbers(ctx, radius) {
        console.log("drawNumbers called"); // Debugging statement
        ctx.font = `${radius * 0.15}px Arial`;
        ctx.textBaseline = 'middle';
        ctx.textAlign = 'center';
        ctx.fillStyle = '#fff';

        for (let num = 1; num <= 12; num++) {
            const angle = num * Math.PI / 6;
            ctx.rotate(angle);
            ctx.translate(0, -radius * 0.8);
            ctx.rotate(-angle);
            ctx.fillText(num.toString(), 0, 0);
            ctx.rotate(angle);
            ctx.translate(0, radius * 0.8);
            ctx.rotate(-angle);
        }
    }

    function drawTime(ctx, radius) {
        console.log("drawTime called"); // Debugging statement
        const now = new Date();
        let hour = now.getHours() % 12;
        let minute = now.getMinutes();
        let second = now.getSeconds();

        // Hour hand
        hour = hour * Math.PI / 6 + minute * Math.PI / (6 * 60) + second * Math.PI / (360 * 60);
        drawHand(ctx, hour, radius * 0.5, radius * 0.07);

        // Minute hand
        minute = minute * Math.PI / 30 + second * Math.PI / (30 * 60);
        drawHand(ctx, minute, radius * 0.75, radius * 0.07);

        // Second hand
        second = second * Math.PI / 30;
        drawHand(ctx, second, radius * 0.85, radius * 0.02, '#ff4081');
    }

    function drawHand(ctx, pos, length, width, color = '#fff') {
        console.log("drawHand called"); // Debugging statement
        ctx.beginPath();
        ctx.lineWidth = width;
        ctx.lineCap = 'round';
        ctx.strokeStyle = color;
        ctx.moveTo(0, 0);
        ctx.rotate(pos);
        ctx.lineTo(0, -length);
        ctx.stroke();
        ctx.rotate(-pos);
    }

    drawClock();
}

// Initialize functions
function initializeClock() {
    console.log("initializeClock called"); // Debugging statement
    updateLastVisit();
    drawAnalogClock();
    updateClock();
    setInterval(updateClock, 1000);
}

// Wait for the DOM to load before initializing
document.addEventListener('DOMContentLoaded', initializeClock);
