// clockwork.js

(function () {
    // Initialization flag to prevent multiple executions
    let clockInitialized = false;

    // Variables to track the last formatted date and day of the week
    let lastFormattedDate = null;
    let lastFormattedDayOfWeek = null;

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
        const secure = location.protocol === 'https:' ? "; Secure" : "";
        const sameSite = "; SameSite=Lax";
        document.cookie = `${name}=${encodeURIComponent(value)}; ${expires}; path=/;${secure}${sameSite}`;
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
     * Checks if the user has consented to necessary cookies.
     * @returns {boolean} True if consented, false otherwise.
     */
    function hasNecessaryConsent() {
        const consent = getCookie('cookieConsent');
        if (consent) {
            try {
                const consentObj = JSON.parse(consent);
                return consentObj.necessary === true;
            } catch (error) {
                console.error('Error parsing cookieConsent:', error);
                return false;
            }
        }
        // If no consent cookie is found, assume no consent
        return false;
    }

    /**
     * Updates the "time since last visit" message using cookies.
     */
    function updateLastVisit() {
        // Check for necessary consent before proceeding
        if (!hasNecessaryConsent()) {
            console.log('Necessary cookies are not consented. Skipping last visit message.');
            return;
        }

        const lastVisitMessageElement = document.getElementById('last-visit-message');
        const lastVisit = getCookie('lastVisit');
        const now = new Date();

        if (lastVisit && lastVisitMessageElement) {
            try {
                const previousVisit = new Date(lastVisit);
                const timeDifference = now - previousVisit;
                const days = Math.floor(timeDifference / (1000 * 60 * 60 * 24));
                const hours = Math.floor((timeDifference / (1000 * 60 * 60)) % 24);
                const minutes = Math.floor((timeDifference / (1000 * 60)) % 60);

                console.log(`Previous Visit: ${previousVisit}`);
                console.log(`Current Time: ${now}`);
                console.log(`Time Difference: ${timeDifference}ms (${days} days, ${hours} hours, ${minutes} minutes)`);

                let message = 'Welcome back! You last visited ';
                if (days > 0) {
                    message += `${days} day(s) `;
                }
                if (hours > 0) {
                    message += `${hours} hour(s) `;
                }
                if (minutes > 0 || (days === 0 && hours === 0)) {
                    message += `${minutes} minute(s) `;
                }
                message += 'ago.';
                lastVisitMessageElement.textContent = message;
            } catch (error) {
                console.error('Error updating last visit message:', error);
                if (lastVisitMessageElement) {
                    lastVisitMessageElement.textContent = 'Welcome to my website!';
                }
            }
        } else if (lastVisitMessageElement) {
            try {
                lastVisitMessageElement.textContent = 'Welcome to my website!';
                console.log('No previous visit detected. Displaying welcome message.');
            } catch (error) {
                console.error('Error setting initial welcome message:', error);
            }
        }
    }

    /**
     * Formats the date consistently.
     * @param {Date} date - The date to format.
     * @returns {string} The formatted date string.
     */
    function formatDate(date) {
        const options = { year: 'numeric', month: 'long', day: 'numeric' };
        return date.toLocaleDateString('en-US', options);
    }

    /**
     * Formats the day of the week consistently.
     * @param {Date} date - The date to extract the day from.
     * @returns {string} The formatted day of the week.
     */
    function formatDayOfWeek(date) {
        const options = { weekday: 'long' };
        return date.toLocaleDateString('en-US', options);
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
                // Only update the time text to prevent re-rendering the icon
                const currentTime = now.toLocaleTimeString('en-US', timeOptions);
                const iconHtml = `<i class="fas fa-clock"></i> `;
                if (localTimeElement.innerHTML !== `${iconHtml}${currentTime}`) {
                    localTimeElement.innerHTML = `${iconHtml}${currentTime}`;
                }
            } catch (error) {
                console.error('Error updating local time:', error);
            }
        }

        // Update date
        const currentDateElement = document.getElementById('current-date');
        if (currentDateElement) {
            try {
                const formattedDate = formatDate(now).trim();
                // Only update if the date has changed to prevent unnecessary DOM updates
                if (lastFormattedDate !== formattedDate) {
                    currentDateElement.innerHTML = `<i class="fas fa-calendar-alt"></i> ${formattedDate}`;
                    lastFormattedDate = formattedDate;
                    console.log(`Updated date to: ${formattedDate}`);
                }
            } catch (error) {
                console.error('Error updating current date:', error);
            }
        }

        // Update day of the week
        const dayOfWeekElement = document.getElementById('day-of-week');
        if (dayOfWeekElement) {
            try {
                const formattedDay = formatDayOfWeek(now).trim();
                // Only update if the day has changed
                if (lastFormattedDayOfWeek !== formattedDay) {
                    dayOfWeekElement.innerHTML = `<i class="fas fa-calendar-day"></i> ${formattedDay}`;
                    lastFormattedDayOfWeek = formattedDay;
                    console.log(`Updated day of the week to: ${formattedDay}`);
                }
            } catch (error) {
                console.error('Error updating day of the week:', error);
            }
        }

        // Update time zone
        const timeZoneElement = document.getElementById('time-zone');
        if (timeZoneElement) {
            try {
                const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
                const timeZoneText = `Time Zone: ${timeZone}`;
                const iconHtml = `<i class="fas fa-globe"></i> `;
                if (timeZoneElement.innerHTML !== `${iconHtml}${timeZoneText}`) {
                    timeZoneElement.innerHTML = `${iconHtml}${timeZoneText}`;
                }
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
                if (greetingElement.textContent !== greeting) {
                    greetingElement.textContent = greeting;
                }
            } catch (error) {
                console.error('Error updating greeting:', error);
            }
        }
    }

    /**
     * Updates the "last visit" cookie when the user is about to leave the page.
     */
    function updateLastVisitOnUnload() {
        // Check for necessary consent before setting the cookie
        if (!hasNecessaryConsent()) {
            console.log("Consent not given. 'lastVisit' cookie will not be set.");
            return;
        }
        try {
            const now = new Date();
            setCookie('lastVisit', now.toISOString(), 365);
            console.log(`Set 'lastVisit' cookie to ${now.toISOString()}`);
        } catch (error) {
            console.error('Error updating last visit in cookies on unload:', error);
        }
    }

    /**
     * Initializes the clock by setting up event listeners and starting updates.
     */
    function initializeClock() {
        if (clockInitialized) return;
        clockInitialized = true;

        updateLastVisit();
        updateClock();
        setInterval(updateClock, 1000);

        // Update 'lastVisit' cookie when the user is about to leave the page
        window.addEventListener('beforeunload', updateLastVisitOnUnload);

        // Initialize Animations using Anime.js
        initializeAnimations();
    }

    /**
     * Initializes animations using Anime.js for the now-playing box and widgets.
     */
    function initializeAnimations() {
        // Ensure Anime.js is loaded
        if (typeof anime === 'undefined') {
            console.error('Anime.js is not loaded. Please include the Anime.js library.');
            return;
        }

        // Animate the now-playing box
        anime({
            targets: '#nowPlayingBox',
            opacity: [0, 1],
            translateY: [-50, 0],
            easing: 'easeOutExpo',
            duration: 1000
        });

        // Animate the weather section
        anime({
            targets: '.weather-section',
            opacity: [0, 1],
            translateX: [50, 0],
            easing: 'easeOutExpo',
            duration: 1000,
            delay: 200
        });

        // Animate the clock section
        anime({
            targets: '.clock-section',
            opacity: [0, 1],
            translateY: [50, 0],
            easing: 'easeOutExpo',
            duration: 1000,
            delay: 400
        });

        // Animate the footer
        anime({
            targets: '.footer',
            opacity: [0, 1],
            translateY: [100, 0],
            easing: 'easeOutExpo',
            duration: 1000,
            delay: 600
        });

        // Optional: Animate individual widgets within the now-playing box
        anime({
            targets: '.now-playing-sidebar .sidebar-item',
            opacity: [0, 1],
            translateX: [-20, 0],
            easing: 'easeOutExpo',
            duration: 800,
            delay: anime.stagger(100, { start: 800 }) // Start after main animations
        });

        anime({
            targets: '.video-section .video-title-container h2',
            scale: [0.5, 1],
            opacity: [0, 1],
            easing: 'easeOutElastic(1, .8)',
            duration: 1000
        });

        anime({
            targets: '.video-section .thumbnail-container',
            scale: [0.8, 1],
            opacity: [0, 1],
            easing: 'easeOutExpo',
            duration: 1000,
            delay: 200
        });
    }

    // Wait for the DOM to load before initializing
    document.addEventListener('DOMContentLoaded', () => {
        try {
            initializeClock();
        } catch (error) {
            console.error('Error initializing clock:', error);
        }
    });

    // ==================================================
    // Existing Scripts (Ensure no conflicts occur)
    // ==================================================

    // [Assuming other parts of the original script remain here]
})();
