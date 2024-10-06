// clockwork.js

/**
 * Retrieves the value of a CSS variable from the :root selector.
 * @param {string} variableName - The name of the CSS variable (e.g., '--primary-color').
 * @param {string} fallback - The fallback value if the variable is not found.
 * @returns {string} The value of the CSS variable or the fallback.
 */
function getCSSVariable(variableName, fallback = '#ffffff') {
    const rootStyles = getComputedStyle(document.documentElement);
    const value = rootStyles.getPropertyValue(variableName).trim();
    return value || fallback;
}

/**
 * Sets a cookie with the given name, value, and expiration in days.
 * @param {string} name - The name of the cookie.
 * @param {string} value - The value to store.
 * @param {number} days - Number of days until the cookie expires.
 */
function setCookie(name, value, days) {
    const date = new Date();
    date.setTime(date.getTime() + days * 24 * 60 * 60 * 1000);
    const expires = "expires=" + date.toUTCString();
    const encodedValue = encodeURIComponent(value);
    document.cookie = `${name}=${encodedValue}; ${expires}; path=/; SameSite=Lax`;
}

/**
 * Retrieves the value of a cookie by name.
 * @param {string} name - The name of the cookie.
 * @returns {string|null} The value of the cookie or null if not found.
 */
function getCookie(name) {
    const cname = name + "=";
    const decodedCookie = decodeURIComponent(document.cookie);
    const ca = decodedCookie.split(';');
    for (let c of ca) {
        while (c.charAt(0) === ' ') {
            c = c.substring(1);
        }
        if (c.indexOf(cname) === 0) {
            return c.substring(cname.length, c.length);
        }
    }
    return null;
}

/**
 * Updates the clock and related elements on the page.
 */
function updateClock() {
    const now = new Date();

    // Update local time
    const localTimeElement = document.getElementById('local-time');
    const timeOptions = { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false };
    if (localTimeElement) {
        try {
            localTimeElement.textContent = now.toLocaleTimeString('en-US', timeOptions);
        } catch (error) {
            console.error('Error updating local time:', error);
        }
    }

    // Update date
    const currentDateElement = document.getElementById('current-date');
    const dateOptions = { year: 'numeric', month: 'long', day: 'numeric' }; // Ensure full month name
    if (currentDateElement) {
        try {
            // Specify the locale explicitly, e.g., 'en-US'
            const formattedDate = now.toLocaleDateString('en-US', dateOptions);
            currentDateElement.textContent = formattedDate;
        } catch (error) {
            console.error('Error updating current date:', error);
        }
    }

    // Update day of the week
    const dayOfWeekElement = document.getElementById('day-of-week');
    const dayOptions = { weekday: 'long' };
    if (dayOfWeekElement) {
        try {
            dayOfWeekElement.textContent = now.toLocaleDateString('en-US', dayOptions);
        } catch (error) {
            console.error('Error updating day of the week:', error);
        }
    }

    // Update time zone
    const timeZoneElement = document.getElementById('time-zone');
    if (timeZoneElement) {
        try {
            const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
            timeZoneElement.textContent = `Time Zone: ${timeZone}`;
        } catch (error) {
            console.error('Error updating time zone:', error);
        }
    }

    // Update greeting
    const greetingElement = document.getElementById('greeting');
    if (greetingElement) {
        try {
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
            greetingElement.textContent = greeting;
        } catch (error) {
            console.error('Error updating greeting:', error);
        }
    }

    // Optional: Adjust text styling based on time for better readability
    const clockContainer = document.querySelector('.clock-container');
    if (clockContainer) {
        try {
            const hour = now.getHours();
            if (hour >= 6 && hour < 18) {
                // Daytime - lighter text shadow
                clockContainer.style.textShadow = '0 0 5px rgba(255, 255, 255, 0.7)';
            } else {
                // Nighttime - stronger text shadow
                clockContainer.style.textShadow = '0 0 10px rgba(0, 0, 0, 0.7)';
            }
        } catch (error) {
            console.error('Error updating clock container styling:', error);
        }
    }
}

/**
 * Updates the "time since last visit" message using cookies.
 */
function updateLastVisit() {
    const lastVisitMessageElement = document.getElementById('last-visit-message');
    const now = new Date();
    const lastVisit = getCookie('lastVisit');

    if (lastVisit && lastVisitMessageElement) {
        try {
            const previousVisit = new Date(lastVisit);
            console.log(`Previous Visit: ${previousVisit.toISOString()}`); // Debugging
            if (isNaN(previousVisit)) {
                throw new Error('Invalid previous visit date.');
            }

            const timeDifference = now - previousVisit;
            console.log(`Time Difference (ms): ${timeDifference}`); // Debugging

            if (timeDifference < 0) {
                throw new Error('Previous visit date is in the future.');
            }

            const seconds = Math.floor(timeDifference / 1000);
            const minutes = Math.floor(seconds / 60);
            const hours = Math.floor(minutes / 60);
            const days = Math.floor(hours / 24);

            let message = 'Welcome back! You last visited ';
            const parts = [];

            if (days > 0) {
                parts.push(`${days} day(s)`);
            }
            if (hours % 24 > 0) {
                parts.push(`${hours % 24} hour(s)`);
            }
            if (minutes % 60 > 0) {
                parts.push(`${minutes % 60} minute(s)`);
            }
            if (seconds % 60 > 0 && days === 0 && hours === 0 && minutes === 0) {
                parts.push(`${seconds % 60} second(s)`);
            }

            if (parts.length === 0) {
                message += 'just now.';
            } else {
                message += parts.join(' ') + ' ago.';
            }

            lastVisitMessageElement.textContent = message;
            console.log(`Message: ${message}`); // Debugging
        } catch (error) {
            console.error('Error updating last visit message:', error);
            if (lastVisitMessageElement) {
                lastVisitMessageElement.textContent = 'Welcome to my website!';
            }
        }
    } else if (lastVisitMessageElement) {
        try {
            lastVisitMessageElement.textContent = 'Welcome to my website!';
            console.log('First visit: Welcome message displayed.'); // Debugging
        } catch (error) {
            console.error('Error setting initial welcome message:', error);
        }
    }

    // Update last visit time as ISO string for consistency and set cookie for 365 days
    try {
        setCookie('lastVisit', now.toISOString(), 365);
        console.log(`Set lastVisit cookie to: ${now.toISOString()}`); // Debugging
    } catch (error) {
        console.error('Error updating last visit in cookies:', error);
    }
}

/**
 * Draws the analog clock on the canvas.
 */
function drawAnalogClock() {
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

    // Prevent multiple initializations
    if (canvas.getAttribute('data-initialized') === 'true') {
        return;
    }
    canvas.setAttribute('data-initialized', 'true');

    // Retrieve CSS variable values
    const primaryColor = getCSSVariable('--primary-color', '#00e5ff');
    const secondaryColor = getCSSVariable('--secondary-color', '#ff4081');

    const radius = canvas.width / 2;
    ctx.clearRect(0, 0, canvas.width, canvas.height); // Clear any existing drawings
    ctx.translate(radius, radius);
    const clockRadius = radius * 0.90;

    /**
     * Draws the clock face, numbers, and hands.
     */
    function drawClock() {
        drawFace(ctx, clockRadius, primaryColor, secondaryColor);
        drawNumbers(ctx, clockRadius);
        drawTime(ctx, clockRadius);
        requestAnimationFrame(drawClock);
    }

    /**
     * Draws the clock face with gradients.
     * @param {CanvasRenderingContext2D} ctx - The canvas context.
     * @param {number} radius - The radius of the clock.
     * @param {string} primaryColor - The primary color for the gradient.
     * @param {string} secondaryColor - The secondary color for the gradient.
     */
    function drawFace(ctx, radius, primaryColor, secondaryColor) {
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
        grad.addColorStop(0.5, primaryColor); // Use the fetched primaryColor
        grad.addColorStop(1, secondaryColor); // Use the fetched secondaryColor
        ctx.strokeStyle = grad;
        ctx.lineWidth = radius * 0.05;
        ctx.stroke();

        // Center dot
        ctx.beginPath();
        ctx.arc(0, 0, radius * 0.05, 0, 2 * Math.PI);
        ctx.fillStyle = '#fff';
        ctx.fill();
    }

    /**
     * Draws the numbers on the clock face.
     * @param {CanvasRenderingContext2D} ctx - The canvas context.
     * @param {number} radius - The radius of the clock.
     */
    function drawNumbers(ctx, radius) {
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

    /**
     * Draws the clock hands based on the current time.
     * @param {CanvasRenderingContext2D} ctx - The canvas context.
     * @param {number} radius - The radius of the clock.
     */
    function drawTime(ctx, radius) {
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

    /**
     * Draws a single hand on the clock.
     * @param {CanvasRenderingContext2D} ctx - The canvas context.
     * @param {number} pos - The position of the hand in radians.
     * @param {number} length - The length of the hand.
     * @param {number} width - The width of the hand.
     * @param {string} color - The color of the hand.
     */
    function drawHand(ctx, pos, length, width, color = '#fff') {
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

    // Start the clock animation
    drawClock();
}

/**
 * Initializes the clock by setting up event listeners and starting updates.
 */
function initializeClock() {
    updateLastVisit();
    drawAnalogClock();
    updateClock();
    setInterval(updateClock, 1000);
}

// Wait for the DOM to load before initializing
document.addEventListener('DOMContentLoaded', () => {
    try {
        initializeClock();
    } catch (error) {
        console.error('Error initializing clock:', error);
    }
});
