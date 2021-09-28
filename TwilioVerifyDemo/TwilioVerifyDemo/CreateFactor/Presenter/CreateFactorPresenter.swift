//
//  CreateFactorPresenter.swift
//  TwilioVerifyDemo
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

import UIKit
import Foundation
import TwilioVerify

let accessTokenEndpoint = "/security/push-access-token"
let enrollmentEndpoint = "/security/verified-push"

protocol CreateFactorPresentable {
  func createOld(withIdentity identity: String?, accessTokenURL: String?)
  func create(withIdentity identity: String?, accessTokenURL: String?, oauthAccessToken: String?)
  func accessTokenURL() -> String?
}

class CreateFactorPresenter {
  
  private weak var view: CreateFactorView?
  private let twilioVerify: TwilioVerify
  private let accessTokensAPI: AccessTokensAPI
  
  init?(withView view: CreateFactorView, accessTokensAPI: AccessTokensAPI = AccessTokensAPIClient()) {
    self.view = view
    guard let twilioVerify = DIContainer.shared.resolve(type: TwilioVerifyAdapter.self) else {
      return nil
    }
    self.twilioVerify = twilioVerify
    self.accessTokensAPI = accessTokensAPI
  }
}

extension CreateFactorPresenter: CreateFactorPresentable {
    func createOld(withIdentity identity: String?, accessTokenURL: String?) {
    guard let identity = identity, !identity.isEmpty else {
      view?.showAlert(withMessage: "Invalid Identity")
      return
    }
    guard let url = accessTokenURL, !url.isEmpty else {
      view?.showAlert(withMessage: "Invalid URL")
      return
    }
    let deviceToken = pushToken()
    guard !deviceToken.isEmpty else {
      view?.showAlert(withMessage: "Invalid device token for push")
      return
    }
    saveAccessTokenURL(url)
      accessTokensAPI.accessTokens(at: url, identity: identity, success: { [weak self] response in
      guard let strongSelf = self else { return }
      let factorName = "\(identity)'s Factor"
      strongSelf.createFactor(response, withFactorName: factorName, deviceToken: deviceToken, success: { factor in
        strongSelf.verify(factor, success: { _ in
          strongSelf.view?.stopLoader()
          strongSelf.view?.dismissView()
        }) { error in
          guard let strongSelf = self else { return }
          DispatchQueue.main.async {
            strongSelf.view?.showAlert(withMessage: error.errorMessage)
          }
        }
      }) { error in
        guard let strongSelf = self else { return }
        DispatchQueue.main.async {
          strongSelf.view?.showAlert(withMessage: error.errorMessage)
        }
      }
    }) {[weak self] error in
      guard let strongSelf = self else { return }
      DispatchQueue.main.async {
        strongSelf.view?.showAlert(withMessage: error.localizedDescription)
      }
    }
  }
    func create(withIdentity identity: String?, accessTokenURL: String?, oauthAccessToken: String?) {
    guard let url = accessTokenURL, !url.isEmpty else {
      view?.showAlert(withMessage: "Invalid URL")
      return
    }
    guard let oauthToken = oauthAccessToken, !oauthToken.isEmpty else {
      createOld(withIdentity: identity, accessTokenURL: url)
      return
    }
    let deviceToken = pushToken()
    guard !deviceToken.isEmpty else {
      view?.showAlert(withMessage: "Invalid device token for push")
      return
    }
    saveAccessTokenURL(url)
      accessTokensAPI.accessTokensGet(at: url + accessTokenEndpoint, oauthToken: oauthToken, success: { [weak self] response in
      guard let strongSelf = self else { return }
      let factorName = "\(response.identity)'s Factor"
      strongSelf.createFactor(response, withFactorName: factorName, deviceToken: deviceToken, success: { factor in
        strongSelf.verify(factor, success: { _ in
            
            guard let parameters = try? JSONSerialization.data(withJSONObject: ["sid": factor.sid], options: []) else {
              return
            }
            var request = URLRequest(url: URL(string: url + enrollmentEndpoint)!)
            request.httpMethod = "POST"
            request.httpBody = parameters
            request.setValue("Application/json", forHTTPHeaderField: "Content-Type")
            request.setValue("Bearer \(oauthToken)", forHTTPHeaderField: "Authorization")
            
            let task = URLSession.shared.dataTask(with: request) { data, response, error in
                if error != nil {
                return
              }
              guard response != nil else {
                return
              }
              guard let data = data,
                    let _ = try? JSONDecoder().decode(AccessTokenResponse.self, from: data) else {
                return
              }
            }
            task.resume()
          strongSelf.view?.stopLoader()
          strongSelf.view?.dismissView()
        }) { error in
          guard let strongSelf = self else { return }
          DispatchQueue.main.async {
            strongSelf.view?.showAlert(withMessage: error.errorMessage)
          }
        }
      }) { error in
        guard let strongSelf = self else { return }
        DispatchQueue.main.async {
          strongSelf.view?.showAlert(withMessage: error.errorMessage)
        }
      }
    }) {[weak self] error in
      guard let strongSelf = self else { return }
      DispatchQueue.main.async {
        strongSelf.view?.showAlert(withMessage: error.localizedDescription)
      }
    }
  }
  
  func accessTokenURL() -> String? {
    return UserDefaults.standard.value(forKey: Constants.accessTokenURLKey) as? String
  }
}

private extension CreateFactorPresenter {
  
  struct Constants {
    static let accessTokenURLKey = "accessTokenURL"
    static let pushTokenKey = "PushToken"
    static let dummyPushToken = "0000000000000000000000000000000000000000000000000000000000000000"
  }
  
  func saveAccessTokenURL(_ url: String) {
    UserDefaults.standard.set(url, forKey: Constants.accessTokenURLKey)
  }
  
  func pushToken() -> String {
    if TARGET_OS_SIMULATOR == 1 {
      return Constants.dummyPushToken
    }
    return UserDefaults.standard.value(forKey: Constants.pushTokenKey) as? String ?? String()
  }
  
  func createFactor(_ accessToken: AccessTokenResponse, withFactorName factorName: String, deviceToken: String, success: @escaping FactorSuccessBlock, failure: @escaping TwilioVerifyErrorBlock) {
    let payload = PushFactorPayload(
      friendlyName: factorName,
      serviceSid: accessToken.service_sid,
      identity: accessToken.identity,
      pushToken: deviceToken,
      accessToken: accessToken.token
    )
    twilioVerify.createFactor(withPayload: payload, success: success, failure: failure)
  }
  
  func verify(_ factor: Factor, success: @escaping FactorSuccessBlock, failure: @escaping TwilioVerifyErrorBlock) {
    let payload = VerifyPushFactorPayload(sid: factor.sid)
    twilioVerify.verifyFactor(withPayload: payload, success: success, failure: failure)
  }
}
