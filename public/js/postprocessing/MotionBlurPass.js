// /js/postprocessing/MotionBlurPass.js

import * as THREE from '/js/three.module.min.js';
import { Pass } from '/js/postprocessing/Pass.js';
import { ShaderMaterial } from '/js/three.module.min.js';

// Motion Blur Shader
const MotionBlurShader = {
    uniforms: {
        "tDiffuse": { value: null },
        "tOld": { value: null },
        "damp": { value: 0.96 } // Decay factor for accumulation
    },
    vertexShader: `
        varying vec2 vUv;
        void main() {
            vUv = uv;
            gl_Position = projectionMatrix * modelViewMatrix * vec4( position, 1.0 );
        }
    `,
    fragmentShader: `
        uniform sampler2D tDiffuse;
        uniform sampler2D tOld;
        uniform float damp;
        varying vec2 vUv;

        void main() {
            vec4 current = texture2D( tDiffuse, vUv );
            vec4 old = texture2D( tOld, vUv );
            gl_FragColor = mix( current, old, damp );
        }
    `
};

class MotionBlurPass extends Pass {
    constructor() {
        super();

        // Create Shader Material
        this.material = new THREE.ShaderMaterial({
            uniforms: THREE.UniformsUtils.clone(MotionBlurShader.uniforms),
            vertexShader: MotionBlurShader.vertexShader,
            fragmentShader: MotionBlurShader.fragmentShader,
            blending: THREE.NormalBlending,
            transparent: true
        });

        // Create a full-screen quad scene
        this.camera = new THREE.OrthographicCamera(-1, 1, 1, -1, 0, 1);
        this.scene = new THREE.Scene();

        this.quad = new THREE.Mesh(new THREE.PlaneGeometry(2, 2), this.material);
        this.scene.add(this.quad);

        // Create Render Targets
        this.renderTargetOld = new THREE.WebGLRenderTarget(window.innerWidth, window.innerHeight, {
            minFilter: THREE.LinearFilter,
            magFilter: THREE.LinearFilter,
            format: THREE.RGBAFormat
        });

        this.renderTargetCurrent = new THREE.WebGLRenderTarget(window.innerWidth, window.innerHeight, {
            minFilter: THREE.LinearFilter,
            magFilter: THREE.LinearFilter,
            format: THREE.RGBAFormat
        });

        // Initialize the old frame with black
        this.clearOldFrame();
    }

    clearOldFrame() {
        // Render black to the old render target
        const originalClearColor = this.renderer.getClearColor().clone();
        const originalClearAlpha = this.renderer.getClearAlpha();

        this.renderer.setRenderTarget(this.renderTargetOld);
        this.renderer.clearColor();
        this.renderer.clear();

        this.renderer.setClearColor(originalClearColor, originalClearAlpha);
    }

    render(renderer, writeBuffer, readBuffer, deltaTime, maskActive) {
        this.renderer = renderer;

        // Set uniforms
        this.material.uniforms['tDiffuse'].value = readBuffer.texture;
        this.material.uniforms['tOld'].value = this.renderTargetOld.texture;
        this.material.uniforms['damp'].value = 0.96; // Adjust for more or less blur

        // Render the current frame combined with the old frame
        renderer.setRenderTarget(this.renderTargetCurrent);
        renderer.render(this.scene, this.camera);

        // Render to the screen or next pass
        if (this.renderToScreen) {
            renderer.setRenderTarget(null);
        } else {
            renderer.setRenderTarget(writeBuffer);
        }

        this.material.uniforms['tDiffuse'].value = this.renderTargetCurrent.texture;
        renderer.render(this.scene, this.camera);

        // Swap render targets
        const temp = this.renderTargetOld;
        this.renderTargetOld = this.renderTargetCurrent;
        this.renderTargetCurrent = temp;
    }

    setSize(width, height) {
        this.renderTargetOld.setSize(width, height);
        this.renderTargetCurrent.setSize(width, height);
    }
}

export { MotionBlurPass };
