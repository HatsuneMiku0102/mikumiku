// constellation.js

document.addEventListener('DOMContentLoaded', function() {
    // 1. Declare constellationsList at the very top
    let constellationsList = [];

    // 2. Star Catalog with Real Data
    const starCatalog = [
        // Orion
        { name: "Betelgeuse", ra: "05h 55m 10.3053s", dec: "+07° 24′ 25.430″", magnitude: 0.42, spectralType: "M1-M2" },
        { name: "Bellatrix", ra: "05h 25m 07.8632s", dec: "+06° 20′ 59.331″", magnitude: 1.64, spectralType: "B2III" },
        { name: "Saiph", ra: "05h 47m 45.3485s", dec: "-09° 40′ 10.146″", magnitude: 2.07, spectralType: "B0Ia" },
        { name: "Rigel", ra: "05h 14m 32.27210s", dec: "-08° 12′ 05.8981″", magnitude: 0.18, spectralType: "B8I" },
        { name: "Alnilam", ra: "05h 36m 12.8130s", dec: "-01° 12′ 06.9″", magnitude: 1.69, spectralType: "B0Ia" },
        { name: "Alnitak", ra: "05h 40m 45.5277s", dec: "-01° 56′ 33.89″", magnitude: 1.74, spectralType: "O9.5I" },
        { name: "Mintaka", ra: "05h 32m 00.40s", dec: "-00° 17′ 56″", magnitude: 2.23, spectralType: "O9III" },
        
        // Ursa Major
        { name: "Dubhe", ra: "11h 03m 43.6704s", dec: "+61° 45′ 03.89″", magnitude: 1.79, spectralType: "A1IV" },
        { name: "Merak", ra: "11h 01m 50.498s", dec: "+56° 22′ 57.5″", magnitude: 2.37, spectralType: "A1IV" },
        { name: "Phecda", ra: "11h 53m 50.490s", dec: "+53° 41′ 41.9″", magnitude: 2.44, spectralType: "A0IV" },
        { name: "Megrez", ra: "12h 15m 21.408s", dec: "+56° 05′ 17.3″", magnitude: 3.31, spectralType: "A3V" },
        { name: "Alioth", ra: "12h 54m 01.72s", dec: "+55° 57′ 34.9″", magnitude: 1.76, spectralType: "A0V" },
        { name: "Mizar", ra: "13h 23m 55.95s", dec: "+54° 55′ 31.3″", magnitude: 2.23, spectralType: "A2V" },
        { name: "Alkaid", ra: "13h 47m 32.49s", dec: "+49° 20′ 48.1″", magnitude: 1.85, spectralType: "B3V" },
        
        // Cassiopeia
        { name: "Schedar", ra: "01h 55m 07.8s", dec: "+56° 22′ 58.4″", magnitude: 2.23, spectralType: "K0III" },
        { name: "Caph", ra: "02h 22m 56.2s", dec: "+56° 36′ 52.2″", magnitude: 2.28, spectralType: "B8III" },
        { name: "Gamma Cassiopeiae", ra: "00h 08m 23.52s", dec: "+60° 43′ 33.1″", magnitude: 2.48, spectralType: "B0.5IVe" },
        { name: "Ruchbah", ra: "00h 34m 43.7s", dec: "+60° 56′ 46.1″", magnitude: 2.32, spectralType: "K0III" },
        { name: "Segin", ra: "00h 16m 03.0s", dec: "+58° 42′ 44.3″", magnitude: 3.40, spectralType: "F0IV" },
        { name: "Tsih", ra: "00h 38m 37.0s", dec: "+56° 33′ 34.6″", magnitude: 4.51, spectralType: "A5V" },
        
        // Cygnus
        { name: "Deneb", ra: "20h 41m 25.915s", dec: "+45° 16′ 49.2″", magnitude: 1.25, spectralType: "A2Ia" },
        { name: "Albireo", ra: "19h 52m 41.50s", dec: "+27° 57′ 18.0″", magnitude: 3.15, spectralType: "K1V + B8V" },
        { name: "Sadr", ra: "20h 46m 43.27s", dec: "+40° 12′ 56.3″", magnitude: 3.56, spectralType: "A0V" },
        { name: "Gienah", ra: "20h 42m 42.39s", dec: "+44° 09′ 05.0″", magnitude: 2.11, spectralType: "A5V" },
        { name: "Delta Cygni", ra: "20h 37m 59.61s", dec: "+38° 06′ 21.5″", magnitude: 2.63, spectralType: "B5V" },
        { name: "Epsilon Cygni", ra: "20h 33m 14.96s", dec: "+42° 16′ 34.5″", magnitude: 3.77, spectralType: "A1V" },
        { name: "Zeta Cygni", ra: "20h 46m 51.53s", dec: "+44° 25′ 25.6″", magnitude: 3.04, spectralType: "B6V" },
        { name: "Eta Cygni", ra: "20h 35m 00.90s", dec: "+40° 55′ 43.2″", magnitude: 4.37, spectralType: "A2V" },
        
        // Scorpius
        { name: "Antares", ra: "16h 29m 24.459s", dec: "-26° 25′ 55.2″", magnitude: 0.96, spectralType: "M1.5Iab-Ib" },
        { name: "Shaula", ra: "17h 33m 34.21s", dec: "-37° 06′ 32.1″", magnitude: 1.62, spectralType: "B0.5IV" },
        { name: "Sargas", ra: "17h 48m 02.96s", dec: "-40° 47′ 11.1″", magnitude: 2.86, spectralType: "A0III" },
        { name: "Girtab", ra: "17h 43m 18.29s", dec: "-40° 20′ 30.2″", magnitude: 3.62, spectralType: "K5V" },
        { name: "Jabbah", ra: "17h 55m 16.44s", dec: "-34° 21′ 37.6″", magnitude: 3.29, spectralType: "G9III" },
        { name: "Dschubba", ra: "17h 34m 36.28s", dec: "-31° 31′ 14.7″", magnitude: 3.20, spectralType: "K2III" },
        { name: "Akrab", ra: "16h 56m 28.0s", dec: "-26° 29′ 24.0″", magnitude: 3.85, spectralType: "B2V" },
        { name: "Alniyat", ra: "17h 00m 30.0s", dec: "-24° 25′ 00.0″", magnitude: 4.92, spectralType: "F0V" }
        // Add more stars as needed
    ];
    
    // 3. Define Utility Functions
    /**
     * Parses Right Ascension (RA) string to decimal degrees.
     * @param {string} raStr - RA in format "05h 55m 10.3053s"
     * @returns {number} - RA in decimal degrees
     */
    function parseRA(raStr) {
        const raRegex = /(\d+)h\s+(\d+)m\s+([\d.]+)s/;
        const match = raStr.match(raRegex);
        if (!match) return 0;
        const hours = parseInt(match[1], 10);
        const minutes = parseInt(match[2], 10);
        const seconds = parseFloat(match[3]);
        return (hours + minutes / 60 + seconds / 3600) * 15; // 24h = 360 degrees
    }

    /**
     * Parses Declination (Dec) string to decimal degrees.
     * @param {string} decStr - Dec in format "+07° 24′ 25.430″"
     * @returns {number} - Dec in decimal degrees
     */
    function parseDec(decStr) {
        const decRegex = /([+-]?)(\d+)°\s+(\d+)′\s+([\d.]+)″/;
        const match = decStr.match(decRegex);
        if (!match) return 0;
        const sign = match[1] === '-' ? -1 : 1;
        const degrees = parseInt(match[2], 10);
        const minutes = parseInt(match[3], 10);
        const seconds = parseFloat(match[4]);
        return sign * (degrees + minutes / 60 + seconds / 3600);
    }

    /**
     * Converts RA and Dec to Cartesian coordinates.
     * @param {number} ra - Right Ascension in decimal degrees
     * @param {number} dec - Declination in decimal degrees
     * @param {number} canvasWidth - Width of the canvas
     * @param {number} canvasHeight - Height of the canvas
     * @param {number} scale - Scaling factor for projection
     * @returns {Object} - { x, y } coordinates
     */
    function raDecToXY(ra, dec, canvasWidth, canvasHeight, scale = 300) {
        // Convert degrees to radians
        const raRad = (ra * Math.PI) / 180;
        const decRad = (dec * Math.PI) / 180;

        // Simple azimuthal equidistant projection
        const x = canvasWidth / 2 + scale * (Math.cos(decRad) * Math.sin(raRad));
        const y = canvasHeight / 2 - scale * (Math.cos(decRad) * Math.cos(raRad));

        return { x, y };
    }

    /**
     * Maps apparent magnitude to star radius and base opacity.
     * Brighter stars have smaller magnitude values.
     * @param {number} magnitude 
     * @returns {Object} - { radius, baseOpacity }
     */
    function mapMagnitudeToAppearance(magnitude) {
        if (magnitude <= 1) {
            return { radius: 5, baseOpacity: 1 };
        } else if (magnitude <= 2) {
            return { radius: 4, baseOpacity: 0.8 };
        } else if (magnitude <= 3) {
            return { radius: 3, baseOpacity: 0.6 };
        } else if (magnitude <= 4) {
            return { radius: 2, baseOpacity: 0.4 };
        } else {
            return { radius: 1.5, baseOpacity: 0.2 };
        }
    }

    /**
     * Maps spectral type to RGB color.
     * Simplified mapping based on star temperatures.
     * @param {string} spectralType 
     * @returns {Object} - { r, g, b }
     */
    function mapSpectralTypeToColor(spectralType) {
        if (spectralType.startsWith("O")) {
            return { r: 155, g: 176, b: 255 }; // Blue
        } else if (spectralType.startsWith("B")) {
            return { r: 170, g: 191, b: 255 }; // Light Blue
        } else if (spectralType.startsWith("A")) {
            return { r: 202, g: 215, b: 255 }; // White
        } else if (spectralType.startsWith("F")) {
            return { r: 248, g: 247, b: 255 }; // Very White
        } else if (spectralType.startsWith("G")) {
            return { r: 255, g: 244, b: 234 }; // Yellowish
        } else if (spectralType.startsWith("K")) {
            return { r: 255, g: 210, b: 161 }; // Orange
        } else if (spectralType.startsWith("M")) {
            return { r: 255, g: 204, b: 111 }; // Red
        } else {
            return { r: 255, g: 255, b: 255 }; // Default White
        }
    }

    // 4. Constellation Definitions (Orion, Ursa Major, Cassiopeia, Cygnus, Scorpius)
    const constellationData = [
        {
            name: "Orion",
            stars: [
                "Betelgeuse",
                "Bellatrix",
                "Saiph",
                "Rigel",
                "Alnilam",
                "Alnitak",
                "Mintaka"
            ],
            connections: [
                [0, 1], [0, 2], [1, 4], [2, 6],
                [4, 5], [5, 6], [1, 3], [2, 3]
            ]
        },
        {
            name: "Ursa Major",
            stars: [
                "Dubhe",
                "Merak",
                "Phecda",
                "Megrez",
                "Alioth",
                "Mizar",
                "Alkaid"
            ],
            connections: [
                [0, 1], [1, 2], [2, 3],
                [3, 4], [4, 5], [5, 6]
            ]
        },
        {
            name: "Cassiopeia",
            stars: [
                "Schedar",
                "Caph",
                "Gamma Cassiopeiae",
                "Ruchbah",
                "Segin",
                "Tsih"
            ],
            connections: [
                [0, 1], [1, 2], [2, 3],
                [3, 4], [4, 5], [5, 1]
            ]
        },
        {
            name: "Cygnus",
            stars: [
                "Deneb",
                "Albireo",
                "Sadr",
                "Gienah",
                "Delta Cygni",
                "Epsilon Cygni",
                "Zeta Cygni",
                "Eta Cygni"
            ],
            connections: [
                [0, 1], [1, 2], [2, 3],
                [3, 4], [4, 5], [5, 6],
                [6, 7]
            ]
        },
        {
            name: "Scorpius",
            stars: [
                "Antares",
                "Shaula",
                "Sargas",
                "Girtab",
                "Jabbah",
                "Dschubba",
                "Akrab",
                "Alniyat"
            ],
            connections: [
                [0, 1], [1, 2], [2, 3],
                [3, 4], [4, 5], [5, 6],
                [6, 7], [7, 1]
            ]
        },
        // Add more constellations as desired
    ];

    // 5. Star Class
    class Star {
        constructor(name, x, y, radius, twinkleSpeed, color, baseOpacity) {
            this.name = name;
            this.x = x;
            this.y = y;
            this.radius = radius;
            this.twinkleSpeed = twinkleSpeed;
            this.baseOpacity = baseOpacity; // Store base opacity for twinkling
            this.opacity = baseOpacity;
            this.twinkleDirection = Math.random() > 0.5 ? 1 : -1;
            this.color = color; // { r, g, b }
        }

        update() {
            this.opacity += this.twinkleSpeed * this.twinkleDirection;
            if (this.opacity <= this.baseOpacity * 0.5) {
                this.opacity = this.baseOpacity * 0.5;
                this.twinkleDirection = 1;
            } else if (this.opacity >= this.baseOpacity) {
                this.opacity = this.baseOpacity;
                this.twinkleDirection = -1;
            }
        }

        draw(ctx) {
            // Draw glow using radial gradient
            const gradient = ctx.createRadialGradient(this.x, this.y, this.radius, this.x, this.y, this.radius * 4);
            gradient.addColorStop(0, `rgba(${this.color.r}, ${this.color.g}, ${this.color.b}, ${this.opacity})`);
            gradient.addColorStop(1, 'rgba(0, 0, 0, 0)');

            ctx.beginPath();
            ctx.arc(this.x, this.y, this.radius * 4, 0, Math.PI * 2);
            ctx.fillStyle = gradient;
            ctx.fill();

            // Draw star
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(${this.color.r}, ${this.color.g}, ${this.color.b}, ${this.opacity})`;
            ctx.fill();
        }
    }

    // 6. Constellation Class
    class Constellation {
        constructor(data, canvasWidth, canvasHeight, exclusionZones = []) {
            this.name = data.name;
            this.stars = [];
            this.connections = data.connections;
            this.canvasWidth = canvasWidth;
            this.canvasHeight = canvasHeight;

            // Define exclusion zones (content boxes) to prevent constellations from spawning there
            this.exclusionZones = exclusionZones;

            // Randomly position and scale the constellation
            this.scale = Math.random() * 200 + 200; // Scale between 200 and 400 pixels

            // Random position ensuring the constellation fits within the canvas and avoids exclusion zones
            this.position = this.getRandomPosition();

            this.generateStars(data.stars);
        }

        getRandomPosition() {
            const padding = this.scale * 2; 
            let x, y;
            let attempts = 0;
            const maxAttempts = 100;

            do {
                x = Math.random() * (this.canvasWidth - 2 * padding) + padding;
                y = Math.random() * (this.canvasHeight - 2 * padding) + padding;
                attempts++;
                if (attempts > maxAttempts) break; // Prevent infinite loop
            } while (this.isInExclusionZone(x, y));

            return { x, y };
        }

        isInExclusionZone(x, y) {
            return this.exclusionZones.some(zone => 
                x > zone.x && x < zone.x + zone.width &&
                y > zone.y && y < zone.y + zone.height
            );
        }

        generateStars(starNames) {
            starNames.forEach(starName => {
                const starInfo = starCatalog.find(star => star.name === starName);
                if (!starInfo) {
                    console.warn(`Star "${starName}" not found in starCatalog.`);
                    return;
                }

                const ra = parseRA(starInfo.ra);
                const dec = parseDec(starInfo.dec);

                // Adjust raDecToXY to center constellations and scale properly
                const { x, y } = raDecToXY(
                    ra, 
                    dec, 
                    this.canvasWidth / 2, // Center horizontally
                    this.canvasHeight / 2, // Center vertically
                    this.scale
                );

                // Ensure stars are within canvas bounds after centering and scaling
                if (
                    x + this.position.x < 0 || 
                    x + this.position.x > this.canvasWidth || 
                    y + this.position.y < 0 || 
                    y + this.position.y > this.canvasHeight
                ) {
                    console.warn(`Star "${starName}" position is out of canvas bounds.`);
                    return;
                }

                const appearance = mapMagnitudeToAppearance(starInfo.magnitude);
                const color = mapSpectralTypeToColor(starInfo.spectralType);

                this.stars.push(new Star(
                    starInfo.name,
                    x + this.position.x, 
                    y + this.position.y,
                    appearance.radius,
                    0.002, 
                    color,
                    appearance.baseOpacity
                ));
            });

            console.log(`Constellation "${this.name}" generated with ${this.stars.length} stars.`);
        }


        update() {
            this.stars.forEach(star => star.update());
        }

        draw(ctx) {
            // Draw connections
            ctx.strokeStyle = 'rgba(255, 255, 255, 0.4)';
            ctx.lineWidth = 1;
            this.connections.forEach(connection => {
                const [indexA, indexB] = connection;
                const starA = this.stars[indexA];
                const starB = this.stars[indexB];
                if (starA && starB) {
                    ctx.beginPath();
                    ctx.moveTo(starA.x, starA.y);
                    ctx.lineTo(starB.x, starB.y);
                    ctx.stroke();
                }
            });

            // Draw stars
            this.stars.forEach(star => star.draw(ctx));
        }

        /**
         * Check if a given point is within any of the stars
         * @param {number} x 
         * @param {number} y 
         * @returns {Star|null}
         */
        getStarAtPosition(x, y) {
            for (let star of this.stars) {
                const dx = x - star.x;
                const dy = y - star.y;
                const distance = Math.sqrt(dx * dx + dy * dy);
                if (distance <= star.radius * 4) { // Check within the glow radius
                    return star;
                }
            }
            return null;
        }
    }

    // 7. Initialize Canvas and Constellations
    const canvasElement = document.getElementById('techCanvas');
    const ctx = canvasElement.getContext('2d');

    /**
     * Get exclusion zones based on content boxes
     * @returns {Array} - Array of exclusion zone objects
     */
    function getExclusionZones() {
        const zones = [];
        const contentBoxes = document.querySelectorAll('.box-container'); // Adjust selector as needed
        contentBoxes.forEach(box => {
            const rect = box.getBoundingClientRect();
            zones.push({
                x: rect.left,
                y: rect.top,
                width: rect.width,
                height: rect.height
            });
        });
        console.log(`Exclusion zones calculated: ${zones.length}`);
        return zones;
    }

    /**
     * Resize the canvas to fit the window and reinitialize constellations
     */
    function resizeCanvas() {
        canvasElement.width = window.innerWidth;
        canvasElement.height = window.innerHeight;
        initializeConstellations(); // Reinitialize constellations after resizing
    }

    // Event listener for window resize
    window.addEventListener('resize', resizeCanvas);

    // Initial canvas setup
    resizeCanvas();

    // 8. Initialize Constellations
    function initializeConstellations() {
        const exclusionZones = getExclusionZones();
        constellationsList = []; // Reset the list
        constellationData.forEach(def => {
            const constel = new Constellation(def, canvasElement.width, canvasElement.height, exclusionZones);
            constellationsList.push(constel);
            console.log(`Constellation "${constel.name}" initialized.`);
        });
        console.log(`Total constellations initialized: ${constellationsList.length}`);
    }

    // 9. Shooting Stars Management
    class ShootingStar {
        constructor(canvasWidth, canvasHeight) {
            this.reset(canvasWidth, canvasHeight);
        }

        reset(canvasWidth, canvasHeight) {
            this.x = Math.random() * canvasWidth;
            this.y = Math.random() * canvasHeight * 0.5; // Appear in the upper half
            this.length = Math.random() * 80 + 20;
            this.speed = Math.random() * 10 + 10;
            this.angle = Math.PI / 4; // 45 degrees
            this.opacity = 1;
            this.alive = true;
        }

        update(canvasWidth, canvasHeight) {
            this.x += Math.cos(this.angle) * this.speed;
            this.y += Math.sin(this.angle) * this.speed;
            this.opacity -= 0.02;
            if (this.opacity <= 0 || this.x > canvasWidth || this.y > canvasHeight) {
                this.alive = false;
            }
        }

        draw(ctx) {
            ctx.beginPath();
            ctx.moveTo(this.x, this.y);
            ctx.lineTo(
                this.x - Math.cos(this.angle) * this.length,
                this.y - Math.sin(this.angle) * this.length
            );
            ctx.strokeStyle = `rgba(255, 255, 255, ${this.opacity})`;
            ctx.lineWidth = 2;
            ctx.stroke();
        }
    }

    const shootingStars = [];
    const shootingStarProbability = 0.002; // Probability per frame to spawn a shooting star

    function manageShootingStars() {
        if (Math.random() < shootingStarProbability) {
            shootingStars.push(new ShootingStar(canvasElement.width, canvasElement.height));
        }

        for (let i = shootingStars.length - 1; i >= 0; i--) {
            shootingStars[i].update(canvasElement.width, canvasElement.height);
            shootingStars[i].draw(ctx);
            if (!shootingStars[i].alive) {
                shootingStars.splice(i, 1);
            }
        }
    }

    // 10. Hover Functionality
    let hoveredStar = null;
    let hoveredConstellation = null;

    // Tooltip Element
    const tooltip = document.getElementById('tooltip') || createTooltip();

    /**
     * Create Tooltip Element if not present
     */
    function createTooltip() {
        const tooltipDiv = document.createElement('div');
        tooltipDiv.id = 'tooltip';
        tooltipDiv.style.position = 'absolute';
        tooltipDiv.style.background = 'rgba(0, 0, 0, 0.7)';
        tooltipDiv.style.color = '#fff';
        tooltipDiv.style.padding = '5px 10px';
        tooltipDiv.style.borderRadius = '4px';
        tooltipDiv.style.pointerEvents = 'none';
        tooltipDiv.style.visibility = 'hidden';
        tooltipDiv.style.zIndex = '1001'; // Higher than any other elements
        tooltipDiv.style.transition = 'opacity 0.3s';
        tooltipDiv.style.fontSize = '12px';
        tooltipDiv.style.maxWidth = '200px';
        document.body.appendChild(tooltipDiv);
        console.log('Tooltip element created.');
        return tooltipDiv;
    }

    /**
     * Get mouse position relative to the canvas
     * @param {MouseEvent} event 
     * @returns {Object} - { x, y }
     */
    function getMousePos(event) {
        const rect = canvasElement.getBoundingClientRect();
        return {
            x: event.clientX - rect.left,
            y: event.clientY - rect.top
        };
    }

    /**
     * Handle hover over stars
     * @param {MouseEvent} event 
     */
    function handleHover(event) {
        const mousePos = getMousePos(event);
        let found = false;

        for (let constel of constellationsList) {
            const star = constel.getStarAtPosition(mousePos.x, mousePos.y);
            if (star) {
                hoveredStar = star;
                hoveredConstellation = constel;
                showTooltip(event.clientX, event.clientY, `⭐ ${star.name}<br>Constellation: ${constel.name}`);
                found = true;
                break;
            }
        }

        if (!found) {
            hoveredStar = null;
            hoveredConstellation = null;
            hideTooltip();
        }
    }

    /**
     * Show tooltip at specified position with content
     * @param {number} x 
     * @param {number} y 
     * @param {string} content 
     */
    function showTooltip(x, y, content) {
        tooltip.innerHTML = content;
        tooltip.style.left = `${x + 10}px`;
        tooltip.style.top = `${y + 10}px`;
        tooltip.style.visibility = 'visible';
        tooltip.style.opacity = '1';
    }

    /**
     * Hide the tooltip
     */
    function hideTooltip() {
        tooltip.style.visibility = 'hidden';
        tooltip.style.opacity = '0';
    }

    // Add event listener for mouse movement
    canvasElement.addEventListener('mousemove', handleHover);
    canvasElement.addEventListener('mouseleave', hideTooltip);
    console.log('Event listeners for hover added to canvas.');

    // 11. Animation Loop
    let lastFrameTime = Date.now();
    const fps = 60;
    const fpsInterval = 1000 / fps;

    function animateBackground() {
        requestAnimationFrame(animateBackground);

        const now = Date.now();
        const elapsed = now - lastFrameTime;

        if (elapsed > fpsInterval) {
            lastFrameTime = now - (elapsed % fpsInterval);

            ctx.clearRect(0, 0, canvasElement.width, canvasElement.height);

            // Update and draw constellations
            constellationsList.forEach(constellation => {
                constellation.update();
                constellation.draw(ctx);
            });

            // Manage shooting stars
            manageShootingStars();

            // Highlight the hovered star
            if (hoveredStar) {
                ctx.beginPath();
                ctx.arc(hoveredStar.x, hoveredStar.y, hoveredStar.radius * 6, 0, Math.PI * 2);
                ctx.strokeStyle = 'rgba(255, 255, 255, 0.8)';
                ctx.lineWidth = 2;
                ctx.stroke();

                // Optional: Draw a surrounding glow
                ctx.beginPath();
                ctx.arc(hoveredStar.x, hoveredStar.y, hoveredStar.radius * 8, 0, Math.PI * 2);
                ctx.strokeStyle = 'rgba(0, 229, 255, 0.5)';
                ctx.lineWidth = 1;
                ctx.stroke();
            }
        }
    }

    animateBackground();
    console.log('Animation loop started.');

    // 12. Optional: Regenerate constellations periodically to keep the background dynamic
    setInterval(() => {
        initializeConstellations();
        console.log('Constellations regenerated.');
    }, 60000); // Regenerate every 60 seconds
});
