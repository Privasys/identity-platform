// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package org.privasys.nativeemrtd

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Matrix
import android.util.Base64
import android.util.Size
import android.view.Surface
import android.view.View
import android.view.ViewGroup
import androidx.annotation.OptIn
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.AspectRatioStrategy
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleOwner
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.latin.TextRecognizerOptions
import expo.modules.kotlin.AppContext
import expo.modules.kotlin.viewevent.EventDispatcher
import expo.modules.kotlin.views.ExpoView
import java.io.ByteArrayOutputStream
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * A live camera preview that reads text from every frame it can keep up with.
 *
 * The photo-page capture used to take a still about once a second and read
 * that, so the holder waited on each attempt and had to line the page up with a
 * guide. Here the text of each frame is read as it arrives and handed to
 * JavaScript with its position, which decides whether it is a machine readable
 * zone. The frame a reading came from is kept, so the picture that goes on to
 * the verifier is the very one that was read. Parity with the iOS view.
 *
 * Nothing is stored and nothing leaves the phone from here.
 */
class MrzScannerView(context: Context, appContext: AppContext) : ExpoView(context, appContext) {
    private val onText by EventDispatcher()
    private val onReady by EventDispatcher()
    private val onCameraError by EventDispatcher()

    private val previewView = PreviewView(context).apply {
        // A TextureView, so the screen's own overlays draw over the preview.
        implementationMode = PreviewView.ImplementationMode.COMPATIBLE
        scaleType = PreviewView.ScaleType.FILL_CENTER
    }

    private var provider: ProcessCameraProvider? = null
    private var preview: Preview? = null
    private var analysis: ImageAnalysis? = null
    private var active = false
    private var attached = false
    private var bound = false
    private var frameId = 0

    private val heldLock = Any()
    private var held: Bitmap? = null

    private companion object {
        // One reader and one thread for every mount of this view.
        val executor: ExecutorService by lazy { Executors.newSingleThreadExecutor() }
        val recognizer by lazy { TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS) }
    }

    /**
     * Keep frames upright as the screen shows them. The screen turns to
     * landscape as this view mounts, and can be flipped end to end without any
     * layout change, so the way it is turned is checked with every frame. The
     * screen, and not the phone's own sense of up, is what counts: a phone held
     * flat over a document has no up.
     */
    private val followScreen = Runnable {
        val rotation = previewView.display?.rotation ?: return@Runnable
        analysis?.let { if (it.targetRotation != rotation) it.targetRotation = rotation }
        preview?.let { if (it.targetRotation != rotation) it.targetRotation = rotation }
    }

    init {
        setBackgroundColor(0xFF000000.toInt())
        // React Native lays its views out itself, so the surface the preview
        // adds for itself is never measured unless it is done here.
        previewView.setOnHierarchyChangeListener(object : OnHierarchyChangeListener {
            override fun onChildViewRemoved(parent: View?, child: View?) = Unit
            override fun onChildViewAdded(parent: View?, child: View?) {
                parent?.measure(
                    MeasureSpec.makeMeasureSpec(measuredWidth, MeasureSpec.EXACTLY),
                    MeasureSpec.makeMeasureSpec(measuredHeight, MeasureSpec.EXACTLY)
                )
                parent?.layout(0, 0, parent.measuredWidth, parent.measuredHeight)
            }
        })
        addView(
            previewView,
            ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
        )
    }

    fun setActive(value: Boolean) {
        active = value
        apply()
    }

    /**
     * The kept frame as a JPEG, cut to the given part of it (fractions of the
     * frame, from its top left). Empty when no frame has been kept.
     */
    fun snapshot(x: Double, y: Double, width: Double, height: Double): String {
        val image = synchronized(heldLock) { held } ?: return ""
        val w = image.width
        val h = image.height
        val left = (x.coerceIn(0.0, 1.0) * w).toInt()
        val top = (y.coerceIn(0.0, 1.0) * h).toInt()
        val right = ((x + width).coerceIn(0.0, 1.0) * w).toInt()
        val bottom = ((y + height).coerceIn(0.0, 1.0) * h).toInt()
        val cut = if (right - left >= 16 && bottom - top >= 16) {
            Bitmap.createBitmap(image, left, top, right - left, bottom - top)
        } else {
            image
        }
        val out = ByteArrayOutputStream()
        cut.compress(Bitmap.CompressFormat.JPEG, 90, out)
        return Base64.encodeToString(out.toByteArray(), Base64.NO_WRAP)
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec)
        previewView.measure(
            MeasureSpec.makeMeasureSpec(MeasureSpec.getSize(widthMeasureSpec), MeasureSpec.EXACTLY),
            MeasureSpec.makeMeasureSpec(MeasureSpec.getSize(heightMeasureSpec), MeasureSpec.EXACTLY)
        )
    }

    override fun onLayout(changed: Boolean, left: Int, top: Int, right: Int, bottom: Int) {
        val width = right - left
        val height = bottom - top
        previewView.measure(
            MeasureSpec.makeMeasureSpec(width, MeasureSpec.EXACTLY),
            MeasureSpec.makeMeasureSpec(height, MeasureSpec.EXACTLY)
        )
        previewView.layout(0, 0, width, height)
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        attached = true
        apply()
    }

    override fun onDetachedFromWindow() {
        attached = false
        apply()
        super.onDetachedFromWindow()
    }

    private fun fail(message: String) {
        post { onCameraError(mapOf("message" to message)) }
    }

    private fun apply() {
        if (active && attached) bind() else unbind()
    }

    private fun unbind() {
        if (!bound) return
        bound = false
        val cameras = provider ?: return
        analysis?.clearAnalyzer()
        listOfNotNull(preview, analysis).forEach {
            try {
                cameras.unbind(it)
            } catch (_: Throwable) {
            }
        }
        preview = null
        analysis = null
    }

    private fun bind() {
        if (bound) return
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            fail("camera permission has not been granted")
            return
        }
        val owner = appContext.currentActivity as? LifecycleOwner
        if (owner == null) {
            fail("the camera could not be opened")
            return
        }
        bound = true
        val future = ProcessCameraProvider.getInstance(context)
        future.addListener({
            // Unmounted, or turned off, while the camera was being found.
            if (!bound) return@addListener
            try {
                val cameras = future.get()
                provider = cameras

                val wide = ResolutionSelector.Builder()
                    .setAspectRatioStrategy(AspectRatioStrategy.RATIO_16_9_FALLBACK_AUTO_STRATEGY)
                    .setResolutionStrategy(
                        ResolutionStrategy(
                            Size(1920, 1080),
                            ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER
                        )
                    )
                    .build()
                val rotation = previewView.display?.rotation ?: Surface.ROTATION_0

                val newPreview = Preview.Builder()
                    .setResolutionSelector(wide)
                    .setTargetRotation(rotation)
                    .build()
                newPreview.surfaceProvider = previewView.surfaceProvider

                val newAnalysis = ImageAnalysis.Builder()
                    .setResolutionSelector(wide)
                    .setTargetRotation(rotation)
                    // Reading takes longer than a frame; frames that arrive
                    // meanwhile are dropped, so this never falls behind.
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()
                newAnalysis.setAnalyzer(executor) { frame -> read(frame) }

                cameras.bindToLifecycle(owner, CameraSelector.DEFAULT_BACK_CAMERA, newPreview, newAnalysis)
                preview = newPreview
                analysis = newAnalysis
                onReady(emptyMap<String, Any>())
            } catch (e: Throwable) {
                bound = false
                fail(e.localizedMessage ?: "the camera could not be opened")
            }
        }, ContextCompat.getMainExecutor(context))
    }

    @OptIn(ExperimentalGetImage::class)
    private fun read(frame: ImageProxy) {
        val media = frame.image
        if (media == null) {
            frame.close()
            return
        }
        post(followScreen)
        val degrees = frame.imageInfo.rotationDegrees
        // Positions come back as the frame looks once turned upright.
        val turned = degrees == 90 || degrees == 270
        val uprightW = if (turned) frame.height else frame.width
        val uprightH = if (turned) frame.width else frame.height

        recognizer.process(InputImage.fromMediaImage(media, degrees))
            .addOnSuccessListener(executor) { text ->
                val lines = ArrayList<Map<String, Any>>()
                var candidate = false
                for (block in text.textBlocks) {
                    for (line in block.lines) {
                        val box = line.boundingBox ?: continue
                        val compact = line.text.replace(" ", "")
                        if (compact.length < 20) continue
                        if (compact.length >= 28 && compact.contains("<<")) candidate = true
                        lines.add(
                            mapOf(
                                "text" to line.text,
                                "x" to box.left.toDouble() / uprightW,
                                "y" to box.top.toDouble() / uprightH,
                                "w" to box.width().toDouble() / uprightW,
                                "h" to box.height().toDouble() / uprightH
                            )
                        )
                    }
                }

                if (candidate) {
                    candidate = try {
                        val raw = frame.toBitmap()
                        val upright = if (degrees != 0) {
                            val turn = Matrix().apply { postRotate(degrees.toFloat()) }
                            Bitmap.createBitmap(raw, 0, 0, raw.width, raw.height, turn, true)
                        } else {
                            raw
                        }
                        synchronized(heldLock) { held = upright }
                        true
                    } catch (_: Throwable) {
                        false
                    }
                }

                frameId += 1
                val payload = mapOf(
                    "frame" to frameId,
                    "width" to uprightW,
                    "height" to uprightH,
                    "held" to candidate,
                    "lines" to lines
                )
                post { onText(payload) }
            }
            .addOnCompleteListener(executor) { frame.close() }
    }
}
