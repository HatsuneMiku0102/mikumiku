// constellation.js

// Star Catalog with Real Data (Orion, Ursa Major, Cassiopeia, Cygnus, Scorpius)
const starCatalog = [
    // Define your star data here or fetch from a JSON file
    // Example:
    // { name: "Betelgeuse", ra: "05h 55m 10.3053s", dec: "+07° 24′ 25.430″", magnitude: 0.42, spectralType: "M1-M2" },
    // Add more stars as needed
];

// Constellation Definitions (Orion, Ursa Major, Cassiopeia, Cygnus, Scorpius)
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
            "Segin",
            "Delta Cygni",
            "Epsilon Cygni",
            "Zeta Cygni",
            "Eta Cygni"
        ],
        connections: [
            [0, 1], [1, 2], [2, 3],
            [3, 4], [4, 5], [5, 6],
            [6, 7], [7, 8]
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
            "Sargas",
            "Dschubba",
            "Jabbah",
            "Akrab",
            "Dschubba",
            "Alniyat"
        ],
        connections: [
            [0, 1], [1, 2], [2, 3],
            [3, 4], [4, 5], [5, 6],
            [6, 7], [7, 8],
            [8, 9], [9, 10], [10, 1]
        ]
    }
];

// Star Class
class Star {
    constructor(name, x, y, radius, twinkleSpeed, color, baseOpacity) {
        this.name = name;
        this.x = x;
        this.y = y;
        this.radius = radius;
        this.twinkleSpeed = twinkleSpeed;
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

// Constellation Class
class Constellation {
    constructor(data, canvasWidth, canvasHeight) {
        this.name = data.name;
        this.stars = [];
        this.connections = data.connections;
        this.canvasWidth = canvasWidth;
        this.canvasHeight = canvasHeight;

        // Randomly position and scale the constellation
        this.scale = Math.random() * 100 + 100; // Scale between 100 and 200 pixels
        // Remove rotation logic to keep constellations static
        // this.rotation = Math.random() * 2 * Math.PI; // Rotation in radians

        // Random position ensuring the constellation fits within the canvas
        this.position = this.getRandomPosition();

        this.generateStars(data.stars);
    }

    getRandomPosition() {
        const padding = this.scale * 2;
        const x = Math.random() * (this.canvasWidth - 2 * padding) + padding;
        const y = Math.random() * (this.canvasHeight - 2 * padding) + padding;
        return { x, y };
    }

    generateStars(starNames) {
        starNames.forEach(starName => {
            const starInfo = starCatalog.find(star => star.name === starName);
            if (!starInfo) return;

            const ra = parseRA(starInfo.ra);
            const dec = parseDec(starInfo.dec);

            const { x, y } = raDecToXY(ra, dec, this.canvasWidth, this.canvasHeight, this.scale);

            // Remove rotation adjustment
            // const rotatedX = (x - this.position.x) * Math.cos(this.rotation) - (y - this.position.y) * Math.sin(this.rotation) + this.position.x;
            // const rotatedY = (x - this.position.x) * Math.sin(this.rotation) + (y - this.position.y) * Math.cos(this.rotation) + this.position.y;

            const appearance = mapMagnitudeToAppearance(starInfo.magnitude);
            const color = mapSpectralTypeToColor(starInfo.spectralType);

            this.stars.push(new Star(starInfo.name, x, y, appearance.radius, 0.002, color, appearance.baseOpacity));
        });
    }

    update() {
        this.stars.forEach(star => star.update());
        // Remove rotation updates to keep constellations static
        // this.rotation += 0.0005 * deltaTime; // Removed rotation
        // this.applyRotation(); // Removed rotation application
    }

    draw(ctx) {
        // Draw connections
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.4)';
        ctx.lineWidth = 1;
        this.connections.forEach(connection => {
            const [starAName, starBName] = connection;
            const starA = this.stars.find(s => s.name === starAName);
            const starB = this.stars.find(s => s.name === starBName);
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
}

// Shooting Star Class (Optional Enhancement)
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

// Utility Functions

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
        return { radius: 3.5, baseOpacity: 1 };
    } else if (magnitude <= 2) {
        return { radius: 2.5, baseOpacity: 0.8 };
    } else if (magnitude <= 3) {
        return { radius: 2, baseOpacity: 0.6 };
    } else if (magnitude <= 4) {
        return { radius: 1.5, baseOpacity: 0.4 };
    } else {
        return { radius: 1, baseOpacity: 0.2 };
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

// Initialize Canvas and Constellations
const canvasElement = document.getElementById('techCanvas');
const ctx = canvasElement.getContext('2d');

// Resize Canvas to Full Screen
function resizeCanvas() {
    canvasElement.width = window.innerWidth;
    canvasElement.height = window.innerHeight;
    initializeConstellations(); // Reinitialize constellations on resize
}
resizeCanvas();
window.addEventListener('resize', resizeCanvas);

// Initialize Constellations
let constellations = [];

function initializeConstellations() {
    constellations = [];
    constellationData.forEach(def => {
        const constel = new Constellation(def, canvasElement.width, canvasElement.height);
        constellations.push(constel);
    });
}

initializeConstellations();

// Shooting Stars Management (Optional Enhancement)
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

// Animation Loop
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
        constellations.forEach(constellation => {
            constellation.update();
            constellation.draw(ctx);
        });

        // Manage shooting stars
        manageShootingStars();
    }
}

animateBackground();

// Optional: Regenerate constellations periodically to keep the background dynamic
setInterval(() => {
    initializeConstellations();
}, 60000); // Regenerate every 60 seconds

// Utility Function Definitions (Ensure these are included in the script)
/**
 * Parses Right Ascension (RA) string to decimal degrees.
 * @param {string} raStr 
 * @returns {number}
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
 * @param {string} decStr 
 * @returns {number}
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
 * @param {number} ra 
 * @param {number} dec 
 * @param {number} canvasWidth 
 * @param {number} canvasHeight 
 * @param {number} scale 
 * @returns {Object}
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
 * @returns {Object}
 */
function mapMagnitudeToAppearance(magnitude) {
    if (magnitude <= 1) {
        return { radius: 3.5, baseOpacity: 1 };
    } else if (magnitude <= 2) {
        return { radius: 2.5, baseOpacity: 0.8 };
    } else if (magnitude <= 3) {
        return { radius: 2, baseOpacity: 0.6 };
    } else if (magnitude <= 4) {
        return { radius: 1.5, baseOpacity: 0.4 };
    } else {
        return { radius: 1, baseOpacity: 0.2 };
    }
}

/**
 * Maps spectral type to RGB color.
 * Simplified mapping based on star temperatures.
 * @param {string} spectralType 
 * @returns {Object}
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
