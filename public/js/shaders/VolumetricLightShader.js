// VolumetricLightShader.js

import * as THREE from '../three.module.min.js'; // Adjust the path based on your project structure

export const VolumetricLightShader = {
    uniforms: {
        "tDiffuse": { value: null }, // Original scene
        "tDepth": { value: null },   // Depth texture
        "lightPosition": { value: new THREE.Vector3(0, 0, 0) }, // Position of the light in world space
        "cameraNear": { value: 0.1 }, // Camera near plane
        "cameraFar": { value: 20000 }, // Camera far plane
        "resolution": { value: new THREE.Vector2(window.innerWidth, window.innerHeight) }, // Screen resolution
        "density": { value: 0.96 }, // Density of the volumetric effect
        "weight": { value: 0.4 },   // Weight of the volumetric effect
        "decay": { value: 0.93 },   // Decay rate of the light
        "exposure": { value: 0.6 }, // Exposure of the volumetric effect
        "fStepSize": { value: 1.0 }, // Step size for ray marching
        "projectionMatrix": { value: new THREE.Matrix4() }, // Projection matrix
        "modelViewMatrix": { value: new THREE.Matrix4() }, // Model-View matrix
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
        uniform float cameraNear;
        uniform float cameraFar;
        uniform vec2 resolution;
        uniform float density;
        uniform float weight;
        uniform float decay;
        uniform float exposure;
        uniform float fStepSize;
        uniform mat4 projectionMatrix;
        uniform mat4 modelViewMatrix;

        varying vec2 vUv;

        float readDepth(sampler2D depthSampler, vec2 coord) {
            float fragCoordZ = texture2D(depthSampler, coord).x;
            float z = fragCoordZ * 2.0 - 1.0; // Back to NDC 
            return (2.0 * cameraNear * cameraFar) / (cameraFar + cameraNear - z * (cameraFar - cameraNear));
        }

        void main() {
            // Get the current fragment's depth
            float depth = readDepth(tDepth, vUv);

            // Reconstruct the world position of the fragment
            vec3 worldPos = vec3(
                (vUv.x * 2.0 - 1.0) * depth * 1.0, // Assuming camera right is along x-axis
                (vUv.y * 2.0 - 1.0) * depth * 1.0, // Assuming camera up is along y-axis
                depth
            );

            // Compute the direction from the fragment to the light
            vec3 lightDir = normalize(lightPosition - worldPos);

            // Number of steps for ray marching
            int steps = 50; // Reduced from 100 for performance
            float stepSize = fStepSize / float(steps);

            // Initialize accumulation variables
            float illuminationDecay = 1.0;
            vec3 col = vec3(0.0);

            // Ray marching loop
            for(int i = 0; i < 50; i++) { // Adjusted to match 'steps'
                if(i >= steps) break;
                vec3 samplePos = worldPos + lightDir * stepSize * float(i);
                
                // Project the sample position back to screen space
                vec4 clipPos = projectionMatrix * modelViewMatrix * vec4(samplePos, 1.0);
                vec3 ndc = clipPos.xyz / clipPos.w;
                vec2 sampleUv = ndc.xy * 0.5 + 0.5;

                // Read the depth at the sample position
                float sampleDepth = readDepth(tDepth, sampleUv);

                // If the sample depth is less than the sample position's depth, there's an occluder
                if(sampleDepth < samplePos.z){
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
