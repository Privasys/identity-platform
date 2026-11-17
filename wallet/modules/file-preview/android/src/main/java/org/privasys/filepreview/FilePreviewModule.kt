// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package org.privasys.filepreview

import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.pdf.PdfRenderer
import android.os.ParcelFileDescriptor
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.io.File
import java.io.FileOutputStream

/**
 * Draws a PDF's pages to images with Android's own PdfRenderer, so the wallet
 * shows the document in its own screen rather than handing it to another app.
 * The page images are written beside the source file, in the wallet's cache;
 * the caller deletes them with the source.
 */
class FilePreviewModule : Module() {
    override fun definition() = ModuleDefinition {
        Name("FilePreview")

        AsyncFunction("renderPdf") { path: String, width: Int, maxPages: Int ->
            val source = File(path)
            val dir = source.parentFile ?: throw IllegalArgumentException("the file has no folder")
            val pageWidth = width.coerceIn(200, 2400)
            val pages = mutableListOf<Map<String, Any>>()
            val descriptor = ParcelFileDescriptor.open(source, ParcelFileDescriptor.MODE_READ_ONLY)
            val renderer = PdfRenderer(descriptor)
            try {
                val count = minOf(renderer.pageCount, maxPages.coerceIn(1, 500))
                for (i in 0 until count) {
                    val page = renderer.openPage(i)
                    try {
                        val height = maxOf(1, (pageWidth.toLong() * page.height / maxOf(1, page.width)).toInt())
                        val bitmap = Bitmap.createBitmap(pageWidth, height, Bitmap.Config.ARGB_8888)
                        bitmap.eraseColor(Color.WHITE)
                        page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                        val out = File(dir, "${source.nameWithoutExtension}-page-$i.png")
                        FileOutputStream(out).use { stream ->
                            bitmap.compress(Bitmap.CompressFormat.PNG, 100, stream)
                        }
                        bitmap.recycle()
                        pages.add(mapOf("uri" to "file://${out.absolutePath}", "width" to pageWidth, "height" to height))
                    } finally {
                        page.close()
                    }
                }
                mapOf("pages" to pages, "pageCount" to renderer.pageCount)
            } finally {
                renderer.close()
                descriptor.close()
            }
        }
    }
}
