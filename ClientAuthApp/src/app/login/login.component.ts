import { Component, NgZone } from '@angular/core';
import { Router } from '@angular/router';
import { CredentialResponse, PromptMomentNotification } from 'google-one-tap';
import { AuthService } from '../services/auth.service';
import { environment } from 'src/enviroments/enviroments';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent {
  private clientId = environment.clientId;

  constructor(
    private router: Router,
    private _ngZone: NgZone,
    private service: AuthService
    ) {}

  ngOnInit():void{
      // @ts-ignore
      window.onGoogleLibraryLoad = () => {
        // @ts-ignore
        google.accounts.id.initialize({
          client_id: this.clientId,
          callback: this.handleCredentialResponse.bind(this),
          auto_select: false,
          cancel_on_tap_outside: true
        });
        // @ts-ignore
        google.accounts.id.renderButton(
        // @ts-ignore
        document.getElementById("buttonDiv"),
          { theme: "outline", size: "large", width: "100%" }
        );
        // @ts-ignore
        google.accounts.id.prompt((notification: PromptMomentNotification) => {});
      };
  }

   handleCredentialResponse(response: CredentialResponse) {
    this.service.loginWithGoogle(response.credential).subscribe({
      next :(x:any) => {
        localStorage.setItem("user","mihailo marcetic");
        this._ngZone.run(() => {
          this.router.navigate(['/logout']);
        })},
      error :(error:any) => {
          console.log(error);
        }
  });
}


}
