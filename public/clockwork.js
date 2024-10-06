// clockwork.js

(function () {
    // Check if the clock has already been initialized
    if (window.clockInitialized) {
        console.log("Clock is already initialized.");
        return;
    }
    window.clockInitialized = true;

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
        document.cookie = `${name}=${value}; ${expires}; path=/;${secure}${sameSite}`;
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
     * Updates the "time since last visit" message using cookies.
     */
    function updateLastVisit() {
        const lastVisitMessageElement = document.getElementById('last-visit-message');
        const now = new Date();
        const lastVisit = getCookie('lastVisit');

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
                if (minutes > 0 && days === 0) {
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

        // Update last visit time as ISO string for consistency and set cookie for 365 days
        try {
            setCookie('lastVisit', now.toISOString(), 365);
            console.log(`Set 'lastVisit' cookie to ${now.toISOString()}`);
        } catch (error) {
            console.error('Error updating last visit in cookies:', error);
        }
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
     * Initializes the clock by setting up event listeners and starting updates.
     */
    function initializeClock() {
        updateLastVisit();
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
})();
