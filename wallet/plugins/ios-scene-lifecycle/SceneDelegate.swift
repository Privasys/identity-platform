// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// Follows ExpoAppSceneDelegate and SceneEventForwarder of Expo SDK 57
// (Copyright 2015-present 650 Industries, MIT), which this SDK does not carry.

// The wallet's window, made from the scene.
//
// An app built with the iOS 27 SDK must use the scene life cycle: iOS 27 ends
// one that does not as it launches. The app delegate still makes the React
// Native factory; the window is made here, when the scene connects, and React
// Native starts in it.
//
// With scenes UIKit no longer tells the app delegate about links, activities
// or the app coming and going, so each is passed on to it here. It hands them
// to the Expo modules that subscribe, and links to React Native's Linking.
//
// Added to the app target by plugins/ios-scene-lifecycle.js, which also names
// this class in Info.plist and takes the window out of the app delegate.

internal import Expo
import React
import UIKit

@objc(WalletSceneDelegate)
class SceneDelegate: UIResponder, UIWindowSceneDelegate {
  var window: UIWindow?

  private var appDelegate: AppDelegate? {
    return UIApplication.shared.delegate as? AppDelegate
  }

  func scene(
    _ scene: UIScene,
    willConnectTo session: UISceneSession,
    options connectionOptions: UIScene.ConnectionOptions
  ) {
    guard let windowScene = scene as? UIWindowScene else {
      return
    }
    guard let appDelegate = appDelegate, let factory = appDelegate.reactNativeFactory else {
      fatalError("SceneDelegate: the app delegate made no React Native factory before the scene connected")
    }

    let window = UIWindow(windowScene: windowScene)
    self.window = window
    // Libraries that read the app delegate's window find the same one.
    appDelegate.window = window

    // A link that starts the app arrives in the connection options. React
    // Native's Linking.getInitialURL reads the launch options, so they are
    // rebuilt from it; the events sent below come before JavaScript listens.
    let webActivity = connectionOptions.userActivities.first {
      $0.activityType == NSUserActivityTypeBrowsingWeb
    }
    factory.startReactNative(
      withModuleName: "main",
      in: window,
      launchOptions: SceneDelegate.launchOptions(
        url: connectionOptions.urlContexts.first?.url,
        userActivity: webActivity
      )
    )

    for context in connectionOptions.urlContexts {
      open(context)
    }
    for activity in connectionOptions.userActivities {
      resume(activity)
    }
  }

  func sceneDidDisconnect(_ scene: UIScene) {
    window = nil
  }

  func sceneDidBecomeActive(_ scene: UIScene) {
    appDelegate?.applicationDidBecomeActive(UIApplication.shared)
  }

  func sceneWillResignActive(_ scene: UIScene) {
    appDelegate?.applicationWillResignActive(UIApplication.shared)
  }

  func sceneWillEnterForeground(_ scene: UIScene) {
    appDelegate?.applicationWillEnterForeground(UIApplication.shared)
  }

  func sceneDidEnterBackground(_ scene: UIScene) {
    appDelegate?.applicationDidEnterBackground(UIApplication.shared)
  }

  func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
    for context in URLContexts {
      open(context)
    }
  }

  func scene(_ scene: UIScene, continue userActivity: NSUserActivity) {
    resume(userActivity)
  }

  // The app delegate's own methods tell React Native's Linking as well as the
  // Expo modules, so a link is announced once.

  private func open(_ context: UIOpenURLContext) {
    var options: [UIApplication.OpenURLOptionsKey: Any] = [:]
    if let source = context.options.sourceApplication {
      options[.sourceApplication] = source
    }
    if let annotation = context.options.annotation {
      options[.annotation] = annotation
    }
    options[.openInPlace] = context.options.openInPlace
    _ = appDelegate?.application(UIApplication.shared, open: context.url, options: options)
  }

  private func resume(_ activity: NSUserActivity) {
    _ = appDelegate?.application(UIApplication.shared, continue: activity, restorationHandler: { _ in })
  }

  /// The launch options Linking.getInitialURL reads, or nil when neither a
  /// link nor a web activity started the app. The keys are spelled out: their
  /// UIApplication accessors are deprecated, and React Native reads these.
  private static func launchOptions(
    url: URL?,
    userActivity: NSUserActivity?
  ) -> [UIApplication.LaunchOptionsKey: Any]? {
    var options: [UIApplication.LaunchOptionsKey: Any] = [:]
    if let url = url {
      options[UIApplication.LaunchOptionsKey(rawValue: "UIApplicationLaunchOptionsURLKey")] = url
    }
    if let userActivity = userActivity {
      options[UIApplication.LaunchOptionsKey(rawValue: "UIApplicationLaunchOptionsUserActivityDictionaryKey")] = [
        "UIApplicationLaunchOptionsUserActivityTypeKey": userActivity.activityType,
        "UIApplicationLaunchOptionsUserActivityKey": userActivity
      ]
    }
    return options.isEmpty ? nil : options
  }
}
