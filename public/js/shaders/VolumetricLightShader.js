// VolumetricLightShader.js

import * as THREE from '../three.module.min.js'; // Adjust the path based on your project structure

export const VolumetricLightShader = {
    uniforms: {
        "tDiffuse": { value: null }, // Original scene
        "tDepth": { value: null },   // Depth texture
        "lightPosition": { value: new THREE.Vector3(0, 0, 0) }, // Position of the light in world space
        "resolution": { value: new THREE.Vector2(window.innerWidth, window.innerHeight) }, // Screen resolution
        "density": { value: 0.96 }, // Density of the volumetric effect
        "weight": { value: 0.4 },   // Weight of the volumetric effect
        "decay": { value: 0.93 },   // Decay rate of the light
        "exposure": { value: 0.6 }, // Exposure of the volumetric effect
        "fStepSize": { value: 1.0 }, // Step size for ray marching
        // Removed projectionMatrix and modelViewMatrix
    },
    vertexShader: `
        varying vec2 vUv;
        void main() {
            vUv = uv;
            gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
        }
    `,
    fragmentShader: `
        uniform sampler2D tDiffuse;
        uniform sampler2D tDepth;
        uniform vec3 lightPosition;
        uniform vec2 resolution;
        uniform float density;
        uniform float weight;
        uniform float decay;
        uniform float exposure;
        uniform float fStepSize;

        varying vec2 vUv;

        float readDepth(sampler2D depthSampler, vec2 coord) {
            float fragCoordZ = texture2D(depthSampler, coord).x;
            float z = fragCoordZ * 2.0 - 1.0; // Back to NDC 
            float cameraNear = 0.1; // Define camera near
            float cameraFar = 20000.0; // Define camera far
            return (2.0 * cameraNear * cameraFar) / (cameraFar + cameraNear - z * (cameraFar - cameraNear));
        }

        void main() {
            // Get the current fragment's depth
            float depth = readDepth(tDepth, vUv);

            // Reconstruct the view space position of the fragment
            // Note: Reconstructing view-space position without projectionMatrix and modelViewMatrix is not straightforward
            // For simplicity, let's skip world position reconstruction

            // Compute the direction from the fragment to the light in screen space
            // Alternatively, compute in view space
            // To avoid using projectionMatrix and modelViewMatrix, use screen-space direction
            // Simplify direction calculation

            // Placeholder: set lightDir to a fixed direction
            vec3 lightDir = normalize(vec3(0.0, 0.0, 1.0));

            // Number of steps for ray marching
            int steps = 50; // Reduced steps
            float stepSize = fStepSize / float(steps);

            // Initialize accumulation variables
            float illuminationDecay = 1.0;
            vec3 col = vec3(0.0);

            // Ray marching loop
            for(int i = 0; i < steps; i++) {
                vec2 sampleUv = vUv + lightDir.xy * stepSize * float(i);
                
                // Read the depth at the sample position
                float sampleDepth = readDepth(tDepth, sampleUv);
                
                // If the sample depth is less than the sample position's depth, there's an occluder
                if(sampleDepth < depth + stepSize * float(i)) {
                    break;
                }
                
                // Accumulate the light
                col += texture2D(tDiffuse, sampleUv).rgb * illuminationDecay;
                illuminationDecay *= decay;
            }

            // Apply density and exposure
            col *= density;
            col *= weight;
            col *= exposure;

            // Combine with the original scene
            vec4 originalColor = texture2D(tDiffuse, vUv);
            gl_FragColor = vec4(originalColor.rgb + col, originalColor.a);
        }
    `
};
