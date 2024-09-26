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

    function parseRA(raStr) {
        const raRegex = /(\d+)h\s+(\d+)m\s+([\d.]+)s/;
        const match = raStr.match(raRegex);
        if (!match) return 0;
        const hours = parseInt(match[1], 10);
        const minutes = parseInt(match[2], 10);
        const seconds = parseFloat(match[3]);
        return (hours + minutes / 60 + seconds / 3600) * 15; // Convert to degrees
    }

    function parseDec(decStr) {
        const decRegex = /([+-]?)(\d+)°\s+(\d+)′\s+([\d.]+)″/;
        const match = decStr.match(decRegex);
        if (!match) return 0;
        const sign = match[1] === '-' ? -1 : 1;
        const degrees = parseInt(match[2], 10);
        const minutes = parseInt(match[3], 10);
        const seconds = parseFloat(match[4]);
        return sign * (degrees + minutes / 60 + seconds / 3600); // Convert to degrees
    }

    // Adjusted raDecToXY function for proper spreading of stars
    function raDecToXY(ra, dec, canvasWidth, canvasHeight) {
        // RA: 0 to 360 degrees, map to 0 to canvasWidth
        const x = (ra / 360) * canvasWidth;

        // Dec: -90 to +90 degrees, map to 0 to canvasHeight
        const y = ((90 - dec) / 180) * canvasHeight;

        console.log(`Adjusted Star position: X=${x}, Y=${y}`);
        
        return { x, y };
    }

    function mapMagnitudeToAppearance(magnitude) {
        // Increase radius and opacity for better visibility
        return { radius: 15, baseOpacity: 1 };
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
            // Twinkling logic
        }

        draw(ctx) {
            const gradient = ctx.createRadialGradient(this.x, this.y, this.radius, this.x, this.y, this.radius * 4);
            gradient.addColorStop(0, `rgba(${this.color.r}, ${this.color.g}, ${this.color.b}, ${this.opacity})`);
            gradient.addColorStop(1, 'rgba(0, 0, 0, 0)');
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.radius * 4, 0, Math.PI * 2);
            ctx.fillStyle = gradient;
            ctx.fill();
        }
    }

    class Constellation {
        constructor(data, canvasWidth, canvasHeight) {
            this.name = data.name;
            this.stars = [];
            this.canvasWidth = canvasWidth;
            this.canvasHeight = canvasHeight;
            this.scale = 100;
            this.generateStars(data.stars);
        }

        generateStars(starNames) {
            starNames.forEach(starName => {
                const starInfo = starCatalog.find(star => star.name === starName);
                if (!starInfo) return;
                const ra = parseRA(starInfo.ra);
                const dec = parseDec(starInfo.dec);
                const { x, y } = raDecToXY(ra, dec, this.canvasWidth, this.canvasHeight);
                const appearance = mapMagnitudeToAppearance(starInfo.magnitude);
                const color = mapSpectralTypeToColor(starInfo.spectralType);
                this.stars.push(new Star(starInfo.name, x, y, appearance.radius, 0.002, color, appearance.baseOpacity));
            });
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
        constellationsList = [];
        constellationData.forEach(def => {
            const constel = new Constellation(def, canvasElement.width, canvasElement.height);
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
