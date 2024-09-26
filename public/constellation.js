document.addEventListener('DOMContentLoaded', function () {
    let constellationsList = [];

    const starCatalog = [
        { name: "Betelgeuse", ra: "05h 55m 10.3053s", dec: "+07° 24′ 25.430″", magnitude: 0.42, spectralType: "M1-M2" },
        { name: "Bellatrix", ra: "05h 25m 07.8632s", dec: "+06° 20′ 59.331″", magnitude: 1.64, spectralType: "B2III" },
        { name: "Saiph", ra: "05h 47m 45.3485s", dec: "-09° 40′ 10.146″", magnitude: 2.07, spectralType: "B0Ia" },
        { name: "Rigel", ra: "05h 14m 32.27210s", dec: "-08° 12′ 05.8981″", magnitude: 0.18, spectralType: "B8I" }
    ];

    const constellationData = [
        {
            name: "Orion",
            stars: ["Betelgeuse", "Bellatrix", "Saiph", "Rigel"],
            connections: [
                [0, 1], [0, 2], [1, 3], [2, 3]
            ]
        }
    ];

    // Function to parse Right Ascension (RA)
    function parseRA(raStr) {
        const raRegex = /(\d+)h\s+(\d+)m\s+([\d.]+)s/;
        const match = raStr.match(raRegex);
        if (!match) return 0;
        const hours = parseInt(match[1], 10);
        const minutes = parseInt(match[2], 10);
        const seconds = parseFloat(match[3]);
        return (hours + minutes / 60 + seconds / 3600) * 15;
    }

    // Function to parse Declination (Dec)
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

    // Function to convert RA/Dec to x/y on canvas
    function raDecToXY(ra, dec, canvasWidth, canvasHeight) {
        const x = (ra / 360) * canvasWidth;
        const y = ((90 - dec) / 180) * canvasHeight;
        return { x, y };
    }

    function mapMagnitudeToAppearance(magnitude) {
        return { radius: 5, baseOpacity: 1 };
    }

    function mapSpectralTypeToColor(spectralType) {
        if (spectralType.startsWith("O")) {
            return { r: 155, g: 176, b: 255 };
        } else if (spectralType.startsWith("B")) {
            return { r: 170, g: 191, b: 255 };
        } else if (spectralType.startsWith("A")) {
            return { r: 202, g: 215, b: 255 };
        } else if (spectralType.startsWith("F")) {
            return { r: 248, g: 247, b: 255 };
        } else if (spectralType.startsWith("G")) {
            return { r: 255, g: 244, b: 234 };
        } else if (spectralType.startsWith("K")) {
            return { r: 255, g: 210, b: 161 };
        } else if (spectralType.startsWith("M")) {
            return { r: 255, g: 204, b: 111 };
        } else {
            return { r: 255, g: 255, b: 255 };
        }
    }

    // Function to get the bounding boxes (exclusion zones) of the widgets
    function getExclusionZones() {
        const exclusionZones = [];
    
        // Add specific elements that should be excluded from star placement
        const widgets = document.querySelectorAll('.now-playing, .live-clock, .weather-widget'); // Add other elements here if needed
    
        widgets.forEach(widget => {
            const rect = widget.getBoundingClientRect();
            exclusionZones.push({
                x: rect.left,
                y: rect.top,
                width: rect.width,
                height: rect.height
            });
        });
    
        console.log('Exclusion Zones:', exclusionZones); // Debug log to ensure zones are captured
        return exclusionZones;
    }

    // Helper function to check if a point is inside any exclusion zone
    function isInExclusionZone(x, y, exclusionZones) {
        for (let zone of exclusionZones) {
            if (x > zone.x && x < zone.x + zone.width && y > zone.y && y < zone.y + zone.height) {
                return true;
            }
        }
        return false;
    }

    class Star {
        constructor(name, x, y, radius, twinkleSpeed, color, baseOpacity) {
            this.name = name;
            this.x = x;
            this.y = y;
            this.radius = radius;
            this.twinkleSpeed = twinkleSpeed;
            this.baseOpacity = baseOpacity;
            this.opacity = baseOpacity;
            this.color = color;
        }
    
        update() {
            this.opacity += this.twinkleSpeed;
            if (this.opacity >= 1) {
                this.twinkleSpeed *= -1;
            } else if (this.opacity <= this.baseOpacity * 0.5) {
                this.twinkleSpeed *= -1;
            }
        }
    
        draw(ctx) {
            // Increase radius and brightness for more vibrant appearance
            const expandedRadius = this.radius * 1.5; // Increase size
            const glowRadius = expandedRadius * 4; // Glow size relative to star size
    
            // Create a glow effect with increased brightness
            const gradient = ctx.createRadialGradient(this.x, this.y, expandedRadius, this.x, this.y, glowRadius);
            gradient.addColorStop(0, `rgba(${this.color.r}, ${this.color.g}, ${this.color.b}, 1)`); // Full brightness
            gradient.addColorStop(1, 'rgba(0, 0, 0, 0)'); // Fade out glow
    
            // Draw glow
            ctx.beginPath();
            ctx.arc(this.x, this.y, glowRadius, 0, Math.PI * 2);
            ctx.fillStyle = gradient;
            ctx.fill();
    
            // Draw the star with higher opacity and larger radius
            ctx.beginPath();
            ctx.arc(this.x, this.y, expandedRadius, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(${this.color.r}, ${this.color.g}, ${this.color.b}, 1)`; // Maximum brightness
            ctx.fill();
        }
    }


    class Constellation {
        constructor(data, canvasWidth, canvasHeight, exclusionZones) {
            this.name = data.name;
            this.stars = [];
            this.canvasWidth = canvasWidth;
            this.canvasHeight = canvasHeight;
            this.exclusionZones = exclusionZones;
            this.generateStars(data.stars);
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
        
                // Convert RA/Dec to X/Y coordinates
                const { x, y } = raDecToXY(ra, dec, this.canvasWidth, this.canvasHeight);
        
                // Clamp positions to canvas size to avoid off-screen rendering
                const clampedX = Math.min(Math.max(0, x), this.canvasWidth);
                const clampedY = Math.min(Math.max(0, y), this.canvasHeight);
        
                // Exclude stars that are inside the exclusion zones
                if (isInExclusionZone(clampedX, clampedY, this.exclusionZones)) {
                    console.log(`Star "${starName}" excluded due to being inside exclusion zone.`);
                    return;
                }
        
                const appearance = mapMagnitudeToAppearance(starInfo.magnitude);
                const color = mapSpectralTypeToColor(starInfo.spectralType);
        
                this.stars.push(new Star(
                    starInfo.name, 
                    clampedX, 
                    clampedY, 
                    appearance.radius, 
                    0.002, 
                    color, 
                    appearance.baseOpacity
                ));
        
                console.log(`Star: ${starInfo.name}, Position: X=${clampedX}, Y=${clampedY}`);
            });
        
            console.log(`Constellation "${this.name}" generated with ${this.stars.length} stars.`);
        }

        update() {
            this.stars.forEach(star => star.update());
        }

        draw(ctx) {
            this.stars.forEach(star => star.draw(ctx));
        }
    }

    const canvasElement = document.getElementById('techCanvas');
    const ctx = canvasElement.getContext('2d');

    function resizeCanvas() {
        canvasElement.width = window.innerWidth;
        canvasElement.height = window.innerHeight;
        initializeConstellations();
    }

    window.addEventListener('resize', resizeCanvas);
    resizeCanvas();

    function initializeConstellations() {
        const exclusionZones = getExclusionZones();
        constellationsList = [];
        constellationData.forEach(def => {
            const constel = new Constellation(def, canvasElement.width, canvasElement.height, exclusionZones);
            constellationsList.push(constel);
        });
    }

    function animateBackground() {
        requestAnimationFrame(animateBackground);
        ctx.clearRect(0, 0, canvasElement.width, canvasElement.height);
        constellationsList.forEach(constellation => {
            constellation.update();
            constellation.draw(ctx);
        });
    }

    animateBackground();
});
